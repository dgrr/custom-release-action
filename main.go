// Package main provides functionality for managing releases and version control in a Gitea repository
package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"code.gitea.io/sdk/gitea"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/hashicorp/go-version"
	gha "github.com/sethvargo/go-githubactions"
)

// VersionAndTag represents a version number and its associated git tag
type VersionAndTag struct {
	Version *version.Version // Semantic version
	Tag     *gitea.Tag       // Git tag information
}

// S3Config contains AWS S3 configuration parameters
type S3Config struct {
	Region    string // AWS region
	Bucket    string // S3 bucket name
	AccessKey string // AWS access key ID
	SecretKey string // AWS secret access key
}

// main is the entry point that handles release management workflow
func main() {
	// Get GitHub Actions context
	ctx, err := gha.Context()
	if err != nil {
		gha.Fatalf("failed to get context: %v", err)
	}

	// ctx.RefName is the branch name, which could be a branch or master, or the tag version
	files := gha.GetInput("files")    // Files to include in release
	apiKey := gha.GetInput("api_key") // Gitea API key
	noRelease := len(gha.GetInput("no_release")) != 0
	if apiKey == "" {
		apiKey = os.Getenv("GITHUB_TOKEN")
	}

	// Initialize S3 config if credentials provided
	var s3Config *S3Config

	region := gha.GetInput("s3_region")
	bucket := gha.GetInput("s3_bucket")
	accessKey := gha.GetInput("s3_access_key")
	secretKey := gha.GetInput("s3_secret_key")

	if region != "" && bucket != "" && accessKey != "" && secretKey != "" {
		s3Config = &S3Config{
			Region:    region,
			Bucket:    bucket,
			AccessKey: accessKey,
			SecretKey: secretKey,
		}
	}

	client := http.DefaultClient

	// Create Gitea client
	c, err := gitea.NewClient(ctx.ServerURL, gitea.SetToken(apiKey), gitea.SetHTTPClient(client))
	if err != nil {
		gha.Fatalf("failed to create gitea client: %v", err)
	}

	owner := ctx.RepositoryOwner
	repo := strings.Split(ctx.Repository, "/")[1]

	// List repo versions and determine which version this is
	tags, _, err := c.ListRepoTags(owner, repo, gitea.ListRepoTagsOptions{
		ListOptions: gitea.ListOptions{
			Page:     0,
			PageSize: 100,
		},
	})
	if err != nil {
		gha.Fatalf("unable to load tags: %v", err)
	}

	// Get closed pull requests
	prs, _, err := c.ListRepoPullRequests(owner, repo, gitea.ListPullRequestsOptions{
		ListOptions: gitea.ListOptions{
			Page:     0,
			PageSize: 100,
		},
		State: gitea.StateClosed,
		Sort:  "recentupdate",
	})
	if err != nil {
		gha.Fatalf("getting pull requests: %s", err)
	}

	// Build version list from tags
	var versions []VersionAndTag
	for _, tag := range tags {
		v, err := version.NewVersion(tag.Name)
		if err != nil {
			log.Fatalf("Unable to parse: %s: %s\n", tag.Name, err)
		}

		versions = append(versions, VersionAndTag{
			Version: v,
			Tag:     tag,
		})
	}

	// Sort versions
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version.LessThan(versions[j].Version)
	})

	if len(versions) != 0 {
		gha.Infof("Existing versions:")
		for i := range versions {
			gha.Infof("  - %s", versions[i].Version)
		}
	}

	if noRelease {
		justUploadFiles(c, ctx, prs, files, versions, s3Config)
	} else {
		configureAndUpload(ctx, prs, versions, c, owner, repo, s3Config, files)
	}
}

// justUploadFiles uploads files to the latest existing release without creating a new one
func justUploadFiles(c *gitea.Client, ctx *gha.GitHubContext, prs []*gitea.PullRequest, files string, versions []VersionAndTag, s3Config *S3Config) {
	if len(versions) == 0 {
		gha.Fatalf("No versions found to upload files to")
	}

	// Get latest version
	newVersion, oldVersion := reconcileVersions(ctx, prs, versions)
	if newVersion == nil {
		gha.Infof("No version returned based of off %s, ignoring", ctx.RefName)
		setOutputs("success", "Nothing happened :)", "")
		return
	}

	if oldVersion != nil {
		gha.Infof("Because there's an old version defined we are going to use it for the release %s -> %s", newVersion, oldVersion)
		newVersion = oldVersion
	} else {
		if len(newVersion.Metadata()) == 0 {
			gha.Infof("Cannot commit to a new release, keeping previous (not %s)", newVersion)
			newVersion = decreaseVersion(newVersion)
		}
	}

	gha.Infof("Using latest version %s for file upload", newVersion)

	owner := ctx.RepositoryOwner
	repo := strings.Split(ctx.Repository, "/")[1]

	// Get matching files
	matchedFiles, err := getFiles(ctx.Workspace, files)
	if err != nil {
		gha.Fatalf("failed to get files: %v", err)
	}

	// Get the release
	release, _, err := c.GetReleaseByTag(owner, repo, newVersion.String())
	if err != nil {
		gha.Fatalf("failed to get release: %v", err)
	}

	// Get current release note
	currentNote := release.Note

	// Get file hashes and append if not already present
	hashes, err := getFileHashes(matchedFiles)
	if err == nil {
		for i, file := range matchedFiles {
			hashLine := fmt.Sprintf("%s: %s", filepath.Base(file), hashes[i])
			if !strings.Contains(currentNote, hashLine) {
				if !strings.HasSuffix(currentNote, "\n") {
					currentNote += "\n"
				}
				currentNote += hashLine + "\n"
			}
		}

		// Update release with new notes
		_, _, err = c.EditRelease(owner, repo, release.ID, gitea.EditReleaseOption{
			Note: currentNote,
		})
		if err != nil {
			gha.Errorf("failed to update release notes with hashes: %v", err)
		}
	}

	uploadAllFiles(c, owner, repo, release, matchedFiles, s3Config)

	setOutputs("success", fmt.Sprintf("Files uploaded to version %s", newVersion), "")
}

// configureAndUpload creates a new release and uploads files to it
func configureAndUpload(ctx *gha.GitHubContext, prs []*gitea.PullRequest, versions []VersionAndTag, c *gitea.Client, owner, repo string, s3Config *S3Config, files string) {
	releaseMsg := "Nothing happened :)"

	newVersion, oldVersion := reconcileVersions(ctx, prs, versions)
	if newVersion == nil {
		gha.Infof("No version returned based of off %s, ignoring", ctx.RefName)
		setOutputs("success", releaseMsg, "")
		return
	}

	note := buildReleaseNotes(c, owner, repo, ctx, newVersion)
	matchedFiles, err := getFiles(ctx.Workspace, files)
	if err != nil {
		gha.Fatalf("failed to get files: %v", err)
	}

	note = appendFileHashes(note, matchedFiles, ctx.SHA)

	releaseMsg = fmt.Sprintf("Version `%s` has been released (%s)", newVersion, ctx.SHA)
	gha.Infof("Creating release %s", newVersion)

	rel := createRelease(c, owner, repo, newVersion, note, ctx.SHA)

	uploadAllFiles(c, owner, repo, rel, matchedFiles, s3Config)

	if oldVersion != nil {
		cleanupOldVersion(c, owner, repo, oldVersion)
	}

	setOutputs("success", releaseMsg, newVersion.String())
}

// buildReleaseNotes generates release notes from CHANGELOG.md if available
func buildReleaseNotes(c *gitea.Client, owner, repo string, ctx *gha.GitHubContext, version *version.Version) string {
	note := version.String()

	data, _, err := c.GetFile(owner, repo, ctx.Ref, "CHANGELOG.md")
	if err == nil {
		gha.Infof("Found CHANGELOG. Including")
		note = string(data)
	}

	return note
}

// appendFileHashes adds file hashes to release notes
func appendFileHashes(note string, files []string, sha string) string {
	hashes, err := getFileHashes(files)
	if err != nil {
		gha.Infof("Unable to get hashes: %s", err)
		return note
	}

	note += "\n\n"
	for i := range hashes {
		note += fmt.Sprintf("%s: %s\n", filepath.Base(files[i]), hashes[i])
	}
	note += fmt.Sprintf("\n\nCommit: %s", sha)
	return note
}

// createRelease creates a new release in the repository
func createRelease(c *gitea.Client, owner, repo string, version *version.Version, note string, sha string) *gitea.Release {
	rel, err := createOrGetRelease(c, owner, repo, true, gitea.CreateReleaseOption{
		TagName:      version.String(),
		IsPrerelease: len(version.Prerelease()) != 0 || len(version.Metadata()) != 0,
		Title:        version.String(),
		Target:       sha,
		Note:         note,
	})
	if err != nil {
		gha.Fatalf("failed to create release: %v", err)
	}
	return rel
}

// uploadAllFiles handles uploading files to both Gitea and S3
func uploadAllFiles(c *gitea.Client, owner, repo string, rel *gitea.Release, files []string, s3Config *S3Config) {
	gha.Infof("Uploading files to %s", rel.TagName)
	if err := uploadFiles(c, owner, repo, rel.ID, files); err != nil {
		gha.Fatalf("Failed to upload files: %v", err)
	}

	for _, file := range files {
		gha.Infof("uploading %s to S3", file)
		if err := uploadToS3(repo, rel.TagName, file, s3Config); err != nil {
			gha.Errorf("unable to upload to s3: %s", err)
		}
	}
}

// cleanupOldVersion removes an old release and its tag
func cleanupOldVersion(c *gitea.Client, owner, repo string, oldVersion *version.Version) {
	gha.Infof("Trying to remove old version %s", oldVersion)
	release, _, err := c.GetReleaseByTag(owner, repo, oldVersion.String())
	if err != nil {
		gha.Fatalf("Old release not found: %s", oldVersion)
	}

	if _, err = c.DeleteRelease(owner, repo, release.ID); err != nil {
		gha.Fatalf("unable to delete release %s: %s", oldVersion, err)
	}

	if _, err := c.DeleteTag(owner, repo, release.TagName); err != nil {
		gha.Fatalf("failed to delete the tag %s: %w", release.TagName)
	}
}

// setOutputs sets GitHub Actions outputs
func setOutputs(status, message, release string) {
	gha.SetOutput("status", status)
	gha.SetOutput("message", message)
	if release != "" {
		gha.SetOutput("release", release)
	}
}

// uploadToS3 uploads a file to AWS S3
func uploadToS3(repo, version, filePath string, s3Config *S3Config) error {
	if s3Config == nil {
		gha.Infof("S3 is not configured")
		return nil
	}

	// Load credentials and create session
	sess := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String(s3Config.Region),
		Credentials: credentials.NewStaticCredentials(s3Config.AccessKey, s3Config.SecretKey, ""),
	}))

	// Create S3 service client
	svc := s3.New(sess)

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file for S3 upload: %w", err)
	}
	defer file.Close()

	// Create input params
	input := &s3.PutObjectInput{
		Bucket: aws.String(s3Config.Bucket),
		Key:    aws.String(repo + "/" + version + "/" + filepath.Base(filePath)),
		Body:   file,
	}

	// Upload to S3
	_, err = svc.PutObject(input)
	if err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	gha.Infof("Successfully uploaded %s to S3 bucket s3://%s/%s", filePath, *input.Bucket, *input.Key)
	return nil
}

// getFileHashes calculates SHA1 hashes for the given files
func getFileHashes(files []string) ([]string, error) {
	hashes := make([]string, 0)
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("failed to open release attachment %s: %w", file, err)
		}

		h := sha1.New()

		_, err = io.Copy(h, f)
		if err != nil {
			return nil, err
		}

		// Get the SHA1 sum
		sum := h.Sum(nil)

		hashes = append(hashes, fmt.Sprintf("%x", sum))
	}

	return hashes, nil
}

// reconcileVersions determines the appropriate version number based on the current state
func reconcileVersions(ctx *gha.GitHubContext, prs []*gitea.PullRequest, versions []VersionAndTag) (*version.Version, *version.Version) {
	// Get the branch/ref name we're working with
	refName := ctx.RefName
	gha.Infof("Determining the version based of off %s: %v", refName, versions)

	// Track if this commit is from a merged branch
	var mergeBranch *string

	// Check if there are any commits in the event
	if commits, ok := ctx.Event["commits"]; ok {
		commits := commits.([]interface{})
		// Loop through commits looking for merge commits
		for _, commit := range commits {
			commit := commit.(map[string]interface{})
			if commitId, ok := commit["id"]; ok {
				gha.Infof("Checking %d pull requests", len(prs))
				// Check if this commit matches a merged PR
				for _, pr := range prs {
					if pr.MergedCommitID != nil {
						gha.Infof("Checking pull request: %v == %s", *pr.MergedCommitID, commitId)
						if *pr.MergedCommitID == commitId.(string) {
							mergeBranch = &pr.Head.Name
							break
						}
					}
				}
			}

			if mergeBranch != nil {
				break
			}
		}
	}

	gha.Infof("Removing branched versions from %v", versions)
	// Filter out versions with metadata to get only stable versions
	versions = slices.DeleteFunc(versions, func(version VersionAndTag) bool {
		return len(version.Version.Metadata()) != 0
	})

	gha.Infof("After removing branched versions %v", versions)

	// Handle different cases based on the branch name
	switch refName {
	case "master", "main":
		// If no versions exist, create initial alpha version
		if len(versions) == 0 {
			gha.Infof("No existing version, creating one")
			return version.Must(version.NewVersion("0.1.0-alpha")), nil
		}

		lastVersion := versions[len(versions)-1]
		// Check if last version was a pre-release
		if len(lastVersion.Version.Prerelease()) != 0 {
			gha.Infof(
				"Previous version %s is a pre-release, checking if we are merging",
				lastVersion.Version,
			)

			// Handle merge case
			if mergeBranch != nil {
				gha.Infof(
					"%s is a merge commit of %s",
					lastVersion.Version, *mergeBranch,
				)

				// Find version with matching branch metadata
				var oldVersion *version.Version
				for _, versionAndTag := range versions {
					if versionAndTag.Version.Metadata() == normalizeBranchName(*mergeBranch) {
						oldVersion = versionAndTag.Version
						break
					}
				}

				return version.Must(
					version.NewVersion(
						lastVersion.Version.Core().String(),
					)), oldVersion
			}

			gha.Infof(
				"%s is a normal push, no merging",
				lastVersion.Version,
			)

			return lastVersion.Version, nil
		}

		// Increment version for stable release
		newVersion := increaseVersion(lastVersion.Version)
		if mergeBranch != nil {
			gha.Infof("Merge committed straight to master without pre-releases, creating new version")

			// Find version with matching branch metadata
			var oldVersion *version.Version
			for _, versionAndTag := range versions {
				gha.Infof("Checking %s <> %s", versionAndTag.Version.Metadata(), normalizeBranchName(*mergeBranch))
				if versionAndTag.Version.Metadata() == normalizeBranchName(*mergeBranch) {
					oldVersion = versionAndTag.Version
					break
				}
			}

			return newVersion, oldVersion
		}

		gha.Infof("Committed to master, releasing a new alpha version of %s", newVersion)

		return version.Must(
			version.NewVersion(
				fmt.Sprintf("%s-alpha", newVersion))), nil
	default:
		// Check if refName is already a version
		_, err := version.NewVersion(refName)
		if err == nil {
			gha.Infof("A new version has been released, ignore")
			return nil, nil
		}

		// Handle branch commits
		branchName := normalizeBranchName(refName)
		gha.Infof("Committed to a branch, releasing a new version with branch metadata: %s", branchName)

		// Look for existing version with this branch metadata
		for _, versionAndTag := range versions {
			if versionAndTag.Version.Metadata() == branchName {
				gha.Infof("Found existing version with metadata %s, using that", branchName)
				return versionAndTag.Version, nil
			}
		}

		// Create new version with branch metadata
		branchVersion := versions[len(versions)-1].Version
		gha.Infof("Version not found for branch %s, using %s", branchName, branchVersion)

		return version.Must(
			version.NewVersion(
				fmt.Sprintf("%s+%s", branchVersion, branchName))), nil
	}
}

// normalizeBranchName converts a branch name to a standardized format
func normalizeBranchName(orig string) string {
	replacer := strings.NewReplacer("_", "-", "/", "-")
	return replacer.Replace(orig)
}

// increaseVersion increments the version number
func increaseVersion(v *version.Version) *version.Version {
	segments := v.Segments()
	for i := len(segments) - 1; i > 0; i-- {
		segments[i] += 1
		if segments[i] < 10 {
			break
		}

		segments[i] = 0
	}

	return version.Must(
		version.NewVersion(
			fmt.Sprintf("%d.%d.%d", segments[0], segments[1], segments[2]),
		),
	)
}

func decreaseVersion(v *version.Version) *version.Version {
	segments := v.Segments()
	for i := len(segments) - 1; i >= 0; i-- {
		segments[i] -= 1
		if segments[i] >= 0 {
			break
		}

		segments[i] = 9
	}

	return version.Must(
		version.NewVersion(
			fmt.Sprintf("%d.%d.%d", segments[0], segments[1], segments[2]),
		),
	)
}

// buildVersionSummary generates a summary of changes between versions
func buildVersionSummary(c *gitea.Client, prevTag *gitea.Tag, owner, repo string) (string, error) {
	msg := "Commits:\n\n"
	page := 0
	lastTime := time.Now()
	// start from the beginning including master
	lastSHA := ""
	index := 1

	requestedSHA := ""

outer:
	for {
		commits, _, err := c.ListRepoCommits(owner, repo, gitea.ListCommitOptions{
			ListOptions: gitea.ListOptions{
				Page:     page,
				PageSize: 100,
			},
			SHA: lastSHA,
		})
		if err != nil {
			return "", err
		}

		if len(requestedSHA) != 0 && requestedSHA == lastSHA {
			break outer
		}

		requestedSHA = lastSHA

		if len(commits) == 0 {
			break outer
		}

		for _, commit := range commits {
			if prevTag != nil {
				if prevTag.Commit.SHA == commit.SHA {
					break outer
				}
			}

			author := func() string {
				if commit.Author != nil {
					return commit.Author.UserName
				}
				return "unknown"
			}()

			lastSHA = commit.SHA

			splitted := strings.Split(commit.RepoCommit.Message, "\n")
			for _, split := range splitted {
				split = strings.TrimPrefix(split, " ")
				split = strings.TrimPrefix(split, "-")
				if len(split) == 0 {
					continue
				}

				sha := commit.SHA[:8]

				msg += fmt.Sprintf("  %d. %s by %s [%s](%s)\n", index, split, author, sha, commit.HTMLURL)
				index++
			}

			if commit.Created.Before(lastTime) {
				lastTime = commit.Created
			}
		}
	}

	return msg, nil
}

// getDirFiles recursively gets all files in a directory
func getDirFiles(dir string) ([]string, error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	info, err := d.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{dir}, nil
	}
	list, err := d.Readdirnames(0)
	if err != nil {
		return nil, err
	}
	res := make([]string, 0, len(list))
	for _, f := range list {
		subs, err := getDirFiles(filepath.Join(dir, f))
		if err != nil {
			return nil, err
		}
		res = append(res, subs...)
	}
	return res, nil
}

// getFiles gets a list of files matching the given patterns
func getFiles(parentDir, files string) ([]string, error) {
	var fileList []string
	lines := strings.Split(files, "\n")
	for _, line := range lines {
		line = strings.Trim(line, "'")
		line = strings.TrimSpace(strings.Trim(line, `"`))
		if line == "" {
			continue
		}
		if filepath.IsAbs(line) {
			return nil, fmt.Errorf("file path %s is absolute", line)
		}
		line = filepath.Join(parentDir, line)
		matches, err := filepath.Glob(line)
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			files, err := getDirFiles(match)
			if err != nil {
				return nil, err
			}
			fileList = append(fileList, files...)
		}
	}
	return fileList, nil
}

// createOrGetRelease creates a new release or gets an existing one
func createOrGetRelease(c *gitea.Client, owner, repo string, deletePreviousTag bool, opts gitea.CreateReleaseOption) (*gitea.Release, error) {
	// Get the release by tag
	release, _, err := c.GetReleaseByTag(owner, repo, opts.TagName)
	if err == nil {
		if !deletePreviousTag {
			release, _, err := c.EditRelease(owner, repo, release.ID, gitea.EditReleaseOption{
				TagName:      opts.TagName,
				Target:       opts.Target,
				Title:        opts.Title,
				Note:         opts.Note,
				IsDraft:      &opts.IsDraft,
				IsPrerelease: &opts.IsPrerelease,
			})
			return release, err
		}

		gha.Infof("Removing tag %s", opts.TagName)

		// Delete the tag if already exists
		if _, err := c.DeleteReleaseByTag(owner, repo, opts.TagName); err != nil {
			return nil, err
		}

		if _, err := c.DeleteTag(owner, repo, opts.TagName); err != nil {
			return nil, err
		}
	} else {
		gha.Infof("%s trying to create it", opts.TagName)
	}

	// Create the release
	release, _, err = c.CreateRelease(owner, repo, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create release: %w", err)
	}

	return release, nil
}

// uploadFiles handles uploading files to a release
func uploadFiles(c *gitea.Client, owner, repo string, releaseID int64, files []string) error {
	attachments, _, err := c.ListReleaseAttachments(owner, repo, releaseID, gitea.ListReleaseAttachmentsOptions{})
	if err != nil {
		return fmt.Errorf("failed to fetch existing release attachments: %w", err)
	}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return fmt.Errorf("failed to open release attachment %s: %w", file, err)
		}

		for _, attachment := range attachments {
			if attachment.Name == filepath.Base(file) {
				if _, err := c.DeleteReleaseAttachment(owner, repo, releaseID, attachment.ID); err != nil {
					f.Close()
					return fmt.Errorf("failed to delete release attachment %s: %w", attachment.Name, err)
				}

				gha.Infof("Successfully deleted old release attachment %s", attachment.Name)
			}
		}

		if _, _, err = c.CreateReleaseAttachment(owner, repo, releaseID, f, filepath.Base(file)); err != nil {
			f.Close()
			return fmt.Errorf("failed to upload release attachment %s: %w", file, err)
		}
		f.Close()

		gha.Infof("Successfully uploaded release attachment %s", file)
	}

	return nil
}
