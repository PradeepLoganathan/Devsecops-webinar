# TAP DevSecOps

> http://tap-gui.tap.mytanzuprod.com/

## review the Tekton pipeline

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
tanzu apps workload create tanzu-dotnet-gitops-app \                                                                       ✔
  --git-branch main \
  --git-repo https://github.com/PradeepLoganathan/Weatherforecast-api \
  --label apps.tanzu.vmware.com/has-tests=true \
  --label app.kubernetes.io/part-of=tanzu-dotnet-gitops-app \
  --type web \
  --namespace application-ns
```