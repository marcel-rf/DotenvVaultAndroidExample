## DotenvVault Android Example


### Install

#### Add jitpack Repository

Add the jitpack repository to you app's build.gradle or settings.gradle


```groovy
repositories {
    maven { url 'https://jitpack.io' }
}
```
   
#### Add Dependency
#### Gradle Groovy DSL
```groovy
implementation 'com.github.dotenv-org:dotenv-vault-kotlin:0.0.1'
```

#### Gradle Kotlin DSL
```kotlin
implementation("com.github.dotenv-org:dotenv-vault-kotlin:0.0.1")
``` 

### Usage

#### Add Dotenv key to your environment

Set your DotenvVault key to your environment variables 
```bash
export DOTENV_KEY="dotenv://....."
```
or Add the key to your `local.properties` file on Android
```bash
DOTENV_KEY=dotenv://.....
```

#### Add vault file to your assets folder
Add `env.vault` (no dot) to your `src/main/assets` folder


### Other Versions
Use the -SNAPSHOT for the latest snapshot version

See all available versions: 
https://jitpack.io/#dotenv-org/dotenv-vault-kotlin/
