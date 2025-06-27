## Don't know how I crossed myself up, but main:main is annoying

### Permanent Fix Steps
- Check if main is also a tag:
```bash
git tag -l main
```
If that returns ```main```, boom—there’s your culprit.

- Delete the local tag named main:
```bash
git tag -d main
```
(This only deletes the tag locally—not on GitHub.)

- Double-check your branches:
```bash
git branch --show-current
```
You should see ```main``` if that’s your current branch.

- Push again:
```bash
git push origin main
```

- If that all works and you want to be extra tidy:- Remove the remote tag too (if it exists):
```bash
git push origin :refs/tags/main
```
That will avoid future conflicts if another clone of the repo has the tag lingering