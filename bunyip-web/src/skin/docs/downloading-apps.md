# Downloading apps

Apps come in two forms: a **container image** you pull with Docker, or a **binary release** you download for your platform. Each app's page on the **Applications** catalog shows whichever ones it offers.

You need to be signed in, and for members-only apps you need an active membership. See [Membership & access](/docs/membership).

## Option 1: pull the container image

If the app offers a container image, its page shows the exact pull details: the registry host, the image reference, and the current version tag.

1. Log in to the registry once. Use the host shown on the app's page in place of `<registry>`, and your account email for the `--username`. Docker prompts for your password:

   ```
   docker login <registry> --username <username>
   ```

2. Pull the image using the reference shown for the app. The full reference is shown so you can copy it directly:

   ```
   docker pull <registry>/<app>:<tag>
   ```

3. Run it following the app's own instructions. For Mokosh, see the Mokosh documentation.

You always get the version currently published for that app, and each published version stays available at its own tag, so pulling a specific tag keeps working after a newer one is released.

## Option 2: download the binary

If the app offers binary downloads, its page lists the release files with the version next to them. Pick the file that matches your operating system and architecture, download it, and run it per the app's instructions.

## Which one should I use?

- Prefer the **container image** if you already run Docker. It bundles everything the app needs to run.
- Prefer the **binary** if you want to run the app directly on your machine without a container.

Not every app offers both. Use whatever its page lists.
