#   Contributing to the project
  
1) Log in to your github
2) Forking the project https://github.com/pkkancharla/CryptoAlgorithms would just create a copy in your account and you cannot yet contribute back to the original repo.
3) Clone your copy of git repo to make changes in your repo. Open the terminal on your computer and clone the project that you have forked.
```
   # git clone https://github.com/<vmkoppula>/CryptoAlgorithms.git
```
4) To contribute back to the original repo https://github.com/pkkancharla/CryptoAlgorithms.git add it as the 'remote upstream' for your local repo clone, this will allow you to fetch updates from the original repo.
```
   # git remote add upstream https://github.com/pkkancharla/CryptoAlgorithms.git
```
5) Pull the any updates.
```
   # git pull upstream master
```   
6) Push any changes from main repo to your forked one.
```
   # git push origin master
```
7) Create a branch for your new changes.
```
   # git checkout -b testcommit
```
8) Do the changes and commit.
```
   # git add <files>
   # git commit -m "this fixes some issue"
```

Before commiting you may set/update you git user identity using 'git config --global --edit'

9) Push the new brach to the remote repo(to the forked repo)
```
   # git push -u origin testcommit
```
10) To merge these changes into the original repo https://github.com/pkkancharla/CryptoAlgorithms, you need to raise a pull request.

   1) Go to the browser and navigate to your fork of the project ( in my case git clone https://github.com/<vmkoppula>/CryptoAlgorithms.git) and you’ll see that your new branch is listed at the top with a handy “Compare & pull request” button. Click on 'Compare & pull request'. And Click on 'Create pull request'

