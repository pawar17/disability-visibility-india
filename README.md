# Disability Visibility India — 2026 rebuild

## What's in this folder

- `index.html` — the whole site in one accessible page (replaces index, learn, resources, support, contact and the 12 condition pages)
- `logo-mark.png`, `aadi.jpg`, `icon.png` — images the page uses
- `apps-script/Code.gs` — the free backend that stores petition signatures and pledges in a Google Sheet you own

## Putting it on disability-visibility.com

1. In the GitHub repo, replace `index.html` with this one and add the three images to the repo root.
2. Delete or keep the old pages. Nothing in the new site links to them.
3. Set up the backend (below), then commit. GitHub Pages updates within a few minutes.

## Turning on petitions and pledges

Follow the steps at the top of `apps-script/Code.gs`, then paste your Web app URL into the page:

```js
const CONFIG = {
  SHEETS_ENDPOINT: "https://script.google.com/macros/s/XXXX/exec"
};
```

Until you do this, the forms show "Signing opens soon".

Your Google Sheet becomes the signature list: full name, email, city, state, petition and whether each person wants updates. Only first name, last initial and city (when the signer opts in) and the counts are ever shown publicly. The script also blocks the same email from signing the same petition twice.

## Keeping it up to date

- News: add an object to the `NEWS` array (newest first is not required; it sorts by date).
- Organisations: edit `DIR` (directory) and `CAUSES` (fundraiser list).
- Petitions: edit `PETS`. Each idea in `CASES` also becomes a petition with the id `idea-<id>`. Keep the ids in `Code.gs` matching.
- Check that every organisation link still works at least once a year. They were carried over from the 2021 site.
