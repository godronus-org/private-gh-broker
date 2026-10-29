# private-gh-broker

POC GitHub sign-in broker for the portal's Deployments tab (frontend GH-20): a stateless OAuth code exchange for the `godronus-org-deploy-bot` GitHub App. Holds only the App's client secret; the connecting user's own GitHub permissions decide what the token reaches. See `src/index.js`.
