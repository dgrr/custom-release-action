package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"code.gitea.io/sdk/gitea"
	"github.com/hashicorp/go-version"
	gha "github.com/sethvargo/go-githubactions"
)

type VersionAndTag struct {
	Version *version.Version
	Tag     *gitea.Tag
}

func main() {
	ctx, err := gha.Context()
	if err != nil {
		gha.Fatalf("failed to get context: %v", err)
	}

	// ctx.RefName is the branch name, which could be a branch or master, or the tag version

	files := gha.GetInput("files")
	apiKey := gha.GetInput("api_key")
	if apiKey == "" {
		apiKey = os.Getenv("GITHUB_TOKEN")
	}

	client := http.DefaultClient

	c, err := gitea.NewClient(ctx.ServerURL, gitea.SetToken(apiKey), gitea.SetHTTPClient(client))
	if err != nil {
		gha.Fatalf("failed to create gitea client: %v", err)
	}

	owner := ctx.RepositoryOwner
	repo := strings.Split(ctx.Repository, "/")[1]

	// list the repo versions and determine which version this is
	tags, _, err := c.ListRepoTags(owner, repo, gitea.ListRepoTagsOptions{
		ListOptions: gitea.ListOptions{
			Page:     0,
			PageSize: 100,
		},
	})
	if err != nil {
		gha.Fatalf("unable to load tags: %v", err)
	}

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

	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version.LessThan(versions[j].Version)
	})

	if len(versions) != 0 {
		gha.Infof("Existing versions:")
		for i := range versions {
			gha.Infof("  - %s", versions[i].Version)
		}
	}

	releaseMsg := "Nothing happened :)"

	newVersion, oldVersion := reconcileVersions(ctx, prs, versions)
	if newVersion == nil {
		gha.Infof("No version returned based of off %s, ignoring", ctx.RefName)
	} else {
		// TODO:
		// msg, err := buildVersionSummary(c, prevTag, owner, repo)
		// if err != nil {
		// 	gha.Fatalf("making summary: %v", err)
		// }

		note := newVersion.String()

		data, _, err := c.GetFile(owner, repo, ctx.Ref, "CHANGELOG.md")
		if err == nil {
			gha.Infof("Found CHANGELOG. Including")
			note = string(data)
		}

		matchedFiles, err := getFiles(ctx.Workspace, files)
		if err != nil {
			gha.Fatalf("failed to get files: %v", err)
		}

		hashes, err := getFileHashes(matchedFiles)
		if err != nil {
			gha.Infof("Unable to get hashes: %s", err)
		} else {
			note += "\n\n"
			for i := range hashes {
				note += fmt.Sprintf("%s: %s\n", filepath.Base(matchedFiles[i]), hashes[i])
			}
		}

		gha.Infof("Creating release %s", newVersion)
		releaseMsg = fmt.Sprintf("Version `%s` has been released", newVersion)

		rel, err := createOrGetRelease(c, owner, repo, gitea.CreateReleaseOption{
			TagName:      newVersion.String(),
			IsPrerelease: len(newVersion.Prerelease()) != 0 || len(newVersion.Metadata()) != 0,
			Title:        newVersion.String(),
			Target:       ctx.SHA,
			Note:         note,
		})
		if err != nil {
			gha.Fatalf("failed to create release: %v", err)
		}

		gha.Infof("Uploading files to %s", rel.TagName)
		if err := uploadFiles(c, owner, repo, rel.ID, matchedFiles); err != nil {
			gha.Fatalf("Failed to upload files: %v", err)
		}

		if oldVersion == nil {
			gha.Infof("No old version present")
		} else {
			gha.Infof("Trying to remove old version %s", oldVersion)
			release, _, err := c.GetReleaseByTag(owner, repo, oldVersion.String())
			if err != nil {
				gha.Fatalf("Old release not found: %s", oldVersion)
			}

			_, err = c.DeleteRelease(owner, repo, release.ID)
			if err != nil {
				gha.Fatalf("unable to delete release %s: %s", oldVersion, err)
			}

			if _, err := c.DeleteTag(owner, repo, release.TagName); err != nil {
				gha.Fatalf("failed to delete the tag %s: %w", release.TagName)
			}
		}

		gha.SetOutput("release", newVersion.String())
	}

	gha.SetOutput("status", "success")
	gha.SetOutput("message", releaseMsg)
}

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

func reconcileVersions(ctx *gha.GitHubContext, prs []*gitea.PullRequest, versions []VersionAndTag) (*version.Version, *version.Version) {
	refName := ctx.RefName
	gha.Infof("Determining the version based of off %s: %v", refName, versions)

	// commit of a merge
	var mergeBranch *string

	if commits, ok := ctx.Event["commits"]; ok {
		commits := commits.([]interface{})
		for _, commit := range commits {
			commit := commit.(map[string]interface{})
			if commitId, ok := commit["id"]; ok {
				gha.Infof("Checking %d pull requests", len(prs))
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

	switch refName {
	case "master", "main":
		if len(versions) == 0 {
			gha.Infof("No existing version, creating one")
			return version.Must(version.NewVersion("0.1.0-alpha")), nil
		}

		lastVersion := versions[len(versions)-1]
		if len(lastVersion.Version.Prerelease()) != 0 {
			gha.Infof(
				"Previous version %s is a pre-release, checking if we are merging",
				lastVersion.Version,
			)

			if mergeBranch != nil {
				gha.Infof(
					"%s is a merge commit of %s",
					lastVersion.Version, *mergeBranch,
				)

				// look for a version containing the branch name
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

		// because the previous is an absolute release (specific version) we need to increase the alpha
		newVersion := increaseVersion(lastVersion.Version)
		if mergeBranch != nil {
			gha.Infof("Merge committed straight to master without pre-releases, creating new version")

			// look for a version containing the branch name
			var oldVersion *version.Version
			for _, versionAndTag := range versions {
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
		_, err := version.NewVersion(refName)
		if err == nil {
			gha.Infof("A new version has been released, ignore")
			// it's a new version
			return nil, nil
		}

		// not a new version, someone pushed to a branch
		// a version must exist if someone has a branch
		branchName := normalizeBranchName(refName)
		gha.Infof("Committed to a branch, releasing a new version with branch metadata: %s", branchName)

		// look for a version containing the branch name
		for _, versionAndTag := range versions {
			if versionAndTag.Version.Metadata() == branchName {
				gha.Infof("Found existing version with metadata %s, using that", branchName)
				return versionAndTag.Version, nil
			}
		}

		branchVersion := versions[len(versions)-1].Version
		gha.Infof("Version not found for branch %s, using %s", branchName, branchVersion)

		return version.Must(
			version.NewVersion(
				fmt.Sprintf("%s+%s", branchVersion, branchName))), nil
		// ...
	}
}

func normalizeBranchName(orig string) string {
	replacer := strings.NewReplacer("_", "-", "/", "-")
	return replacer.Replace(orig)
}

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

func createOrGetRelease(c *gitea.Client, owner, repo string, opts gitea.CreateReleaseOption) (*gitea.Release, error) {
	// Get the release by tag
	release, resp, err := c.GetReleaseByTag(owner, repo, opts.TagName)
	if err == nil {
		// Delete the tag if already exists
		// if _, err := c.DeleteReleaseByTag(owner, repo, opts.TagName); err != nil {
		// 	return nil, err
		// }

		if _, err := c.DeleteTag(owner, repo, opts.TagName); err != nil {
			return nil, err
		}

		tag, _, err := c.CreateTag(owner, repo, gitea.CreateTagOption{
			TagName: opts.TagName,
			Target:  opts.Target,
		})
		if err != nil {
			return nil, err
		}
		_ = tag

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

	errMessage := fmt.Errorf("failed to get release for tag: %s with error: %w", opts.TagName, err)
	if resp.StatusCode != 404 {
		return nil, errMessage
	}

	gha.Infof("%s trying to create it", errMessage)

	// Create the release
	release, _, err = c.CreateRelease(owner, repo, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create release: %w and %s", err, errMessage)
	}

	return release, nil
}

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
