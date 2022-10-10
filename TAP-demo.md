# TAP DevSecOps

## GCP instance

http://tap-gui.tap.mytanzuprod.com/

## Supply chain

### ootb_supply_chain_testing_scanning 

* Watching a Git Repository or local directory for changes.
* Running tests from a developer-provided Tekton Pipeline.
* Scanning the source code for known vulnerabilities using Grype.
* Building a container image out of the source code with Buildpacks.
* Scanning the image for known vulnerabilities.
* Applying operator-defined conventions to the container definition.
* Deploying the application to the same cluster.

Not Done

* Gitops Approval path


## Continous Integration

![](https://i.imgur.com/LCJ2xOf.png)

## Continous Deployment 

![](https://i.imgur.com/cxURe1v.png)


## Review the Tekton pipeline

```yaml=
#tekton pipeline to test a dotnet application
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: tanzu-dotnet-tekton-pipeline
  labels:
    apps.tanzu.vmware.com/pipeline: test      # (!) required
spec:
  params:
    - name: source-url                        # (!) required
    - name: source-revision                   # (!) required
  tasks:
    - name: test
      params:
        - name: source-url
          value: $(params.source-url)
        - name: source-revision
          value: $(params.source-revision)
      taskSpec:
        params:
          - name: source-url
          - name: source-revision
        steps:
          - name: test
            image: bitnami/dotnet-sdk
            script: |-
              dotnet test                    # run dotnet test
```

## Review the Scan policy

```yaml=
apiVersion: scanning.apps.tanzu.vmware.com/v1beta1
kind: ScanPolicy
metadata:
  name: scan-policy
  labels:
    'app.kubernetes.io/part-of': 'scan-system' #! This label is required to have policy visible in tap-gui, but the value can be anything
spec:
  regoFile: |
    package main

    # Accepted Values: "Critical", "High", "Medium", "Low", "Negligible", "UnknownSeverity"
    notAllowedSeverities := ["Critical" ]
    ignoreCves := ["CVE-2018-14643", "CVE-2016-1000027", "GHSA-f2jv-r9rf-7988"]

    contains(array, elem) = true {
      array[_] = elem
    } else = false { true }

    isSafe(match) {
      severities := { e | e := match.ratings.rating.severity } | { e | e := match.ratings.rating[_].severity }
      some i
      fails := contains(notAllowedSeverities, severities[i])
      not fails
    }

    isSafe(match) {
      ignore := contains(ignoreCves, match.id)
      ignore
    }

    deny[msg] {
      comps := { e | e := input.bom.components.component } | { e | e := input.bom.components.component[_] }
      some i
      comp := comps[i]
      vulns := { e | e := comp.vulnerabilities.vulnerability } | { e | e := comp.vulnerabilities.vulnerability[_] }
      some j
      vuln := vulns[j]
      ratings := { e | e := vuln.ratings.rating.severity } | { e | e := vuln.ratings.rating[_].severity }
      not isSafe(vuln)
      msg = sprintf("CVE %s %s %s", [comp.name, vuln.id, ratings])
    } 
```


## Using the accelerator

1. Use the Customer Domain Accelerators.
2. Check for the ability to filter and view acceleratprs

## Creating a new microservice from the accelerator

```shell
#intiailize git
git init -b main

#add code
git add .

#commit the code
git commit -m "initial commit"

#create a github repo, set upstream and push
gh repo create Weatherforecast-api  --public --source=. --remote=upstream --push
```

## Run the service locally

```
dotnet run

curl http://localhost:5006/weatherforecast | jq .
```

## Create a workload and deploy it

```shell=
tanzu apps workload create Weather-API \
  --git-branch main \
  --git-repo https://github.com/PradeepLoganathan/Weatherforecast-api \
  --label apps.tanzu.vmware.com/has-tests=true \
  --label app.kubernetes.io/part-of=tanzu-dotnet-gitops-app \
  --type web \
  --namespace application-ns
```


## Tanzu insights

The Tanzu Insight CLI plug-in enables querying vulnerability, image, and package data.
This can be used to create a CycloneDX based SBOM.

## Query source code information

![](https://i.imgur.com/VqpoI5n.png)


This command gives information about the source code, the package information etc based on the git commit sha.

```shell
tanzu insight source get --commit main/736e45c457d4bca19933d9a96cc61e6ab80d0926
```

## Query images for package and vulnerability info

This command checks a specific image and displays packages & CVEs it contains.

```shell
tanzu insight image packages --digest sha256:3226eadb07724c7ecb47fb9cc48e24a4a8de7f3ef7bacde5923cf131ea09994b --format json  | jq '.[0:10]'
```

We can also get the same information in cyclonedx format as below

```shell
tanzu insight image get --digest sha256:3226eadb07724c7ecb47fb9cc48e24a4a8de7f3ef7bacde5923cf131ea09994b --format cyclonedx
```

We can check an image for vulnerabilites and which packages contain these vulnerabilities

```shell
tanzu insight image vulnerabilities --digest sha256:3226eadb07724c7ecb47fb9cc48e24a4a8de7f3ef7bacde5923cf131ea09994b --format json | jq '.[0:10]'
```

## Query vulnerability information

We can query for packages with vulnerabilities based on a specific CVE ID.



### Find packages with CVE ID - CVE-2016-1000027

This was the CVE which we ignored in the scan policy as it was critical

```shell
tanzu insight vulnerabilities get --cveid CVE-2016-1000027 --format json
```


