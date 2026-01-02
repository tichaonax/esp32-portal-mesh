# esp32-portal-mesh
ESP32 Mesh Portal: Secure guest WiFi access with token-based authentication, captive portal, and REST API management for mesh networks

## Getting Started

### Linking Your Existing Local Repository

If you already have a local repository on your machine and want to link it to this GitHub repository, follow these steps:

#### Option 1: Using HTTPS (Recommended for most users)

1. **Navigate to your local repository:**
   ```bash
   cd /path/to/your/local/repository
   ```

2. **Check your current remotes:**
   ```bash
   git remote -v
   ```

3. **Add this GitHub repository as the remote origin:**
   ```bash
   git remote add origin https://github.com/tichaonax/esp32-portal-mesh.git
   ```
   
   If you already have an origin remote, you can either rename it first:
   ```bash
   git remote rename origin old-origin
   git remote add origin https://github.com/tichaonax/esp32-portal-mesh.git
   ```
   
   Or replace it directly:
   ```bash
   git remote set-url origin https://github.com/tichaonax/esp32-portal-mesh.git
   ```

4. **Fetch the latest changes from GitHub:**
   ```bash
   git fetch origin
   ```

5. **Push your local changes to GitHub:**
   ```bash
   # Push your main/master branch
   git push -u origin main
   
   # Or if you're using master branch:
   git push -u origin master
   ```
   
   If you have a different commit history, you may need to force push (use with caution):
   ```bash
   git push -u origin main --force
   ```

#### Option 2: Using SSH (For users with SSH keys configured)

1. **Navigate to your local repository:**
   ```bash
   cd /path/to/your/local/repository
   ```

2. **Add this GitHub repository as the remote origin using SSH:**
   ```bash
   git remote add origin git@github.com:tichaonax/esp32-portal-mesh.git
   ```

3. **Fetch and push as described in Option 1, steps 4-5**

#### Merging Existing GitHub Content

If the GitHub repository already has commits that you want to integrate with your local repository:

1. **Pull and merge the existing content:**
   ```bash
   git pull origin main --allow-unrelated-histories
   ```

2. **Resolve any conflicts if they occur, then push:**
   ```bash
   git push -u origin main
   ```

#### Starting Fresh

If you want to completely replace the GitHub repository content with your local repository:

1. **Add the remote as described above**
2. **Force push your local repository:**
   ```bash
   git push -u origin main --force
   ```
   
   ⚠️ **Warning:** This will overwrite all content in the GitHub repository!

### Verifying the Connection

After setting up the remote, verify the connection:

```bash
git remote -v
```

You should see output similar to:
```
origin  https://github.com/tichaonax/esp32-portal-mesh.git (fetch)
origin  https://github.com/tichaonax/esp32-portal-mesh.git (push)
```
