## DotenvVaultAndroidExample


### Installing dotenv-vault-kotlin

#### Add jitpack Repository

Add the jitpack repository to you app's build.gradle or settings.gradle


```
allprojects {
		repositories {
			maven { url 'https://jitpack.io' }
		}
	}
```
  
 
 #### Add Dependency
 
``` 
dependencies {
	implementation 'com.github.dotenv-org:dotenv-vault-kotlin:Tag'
}
```




### Running dotenv-vault-kotlin

#### Set your DotenvVault key to your enviroment variables 
export DOTENV_KEY="dotenv://....."
or
add the key to your local.properties file on Android


#### Add vault file to your assets folder
Add env.vault (no dot) to your src/assets folder


#### Versions
Or use the -SNAPSHOT for the latest snapshot version

See all available versions: 
https://jitpack.io/#dotenv-org/dotenv-vault-kotlin/-SNAPSHOT
