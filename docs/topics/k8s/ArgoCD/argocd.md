# ArgoCD

![ArgoCD](ArgoCD-In-The-Middle3.png)
:::note
Images are from [TechWorld with Nana youtube video](https://www.youtube.com/watch?v=MeU5_k9ssrs&t=413s)
:::

## References

:::info
- [ArgoCD Tutorial for Beginners | GitOps CD for Kubernetes](https://www.youtube.com/watch?v=MeU5_k9ssrs&t=413s)
- [ArgoCD Blog](https://blog.argoproj.io/)
:::
 
## What is ArgoCD

- Argo CD is a Continuous Delivery Tool
    ![argocd](argoCD-flow.png)
  - Argo works with a pull method
  - The agent runs within the cluster and monitors your git repo
  - 

## Best practices

- You should have separate git repos for your Source Code and your App Configuration
  - Configuration can include: Deployment, ConfigMap, Secrets
  - 

## Common use cases

## How it works

- ArgoCD will monitor your git repos
- if any change is realized, Argo will sync the changes into your cluster
    ![ArgoCD-Out-Of-Sync](ArgoCD-Out-Of-Sync.png)

- ArgoCD supports the following files
  - K8s YAML Files
  - Helm Charts
  - Kustomize.io

- Splitting CI and CD
    ![Splitting CI/CD](ArgoCD-Splitting-CD-CD.png)
  - You can split up the CI/CD Pipeline
  - CI will be handled by the Developers team
  - CD will be handled by the Operations team

- How to configure ArgoCD
  - Deploy ArgoCD into the K8s Cluster
  - You will setup an application yaml file
    - This file will specify the git repo and the cluster

```
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: sealed-secrets
  namespace: argocd
spec:
  project: default
  source:
    chart: sealed-secrets
    repoURL: https://bitnami-labs.github.io/sealed-secrets
    targetRevision: 1.16.1
    helm:
      releaseName: sealed-secrets
  destination:
    server: "https://kubernetes.default.svc"
    namespace: kubeseal
```

- Multiple clusters
    ![Multiple Clusters](ArgoCD-Multiple-Cluster.png)
  - You can run 1 instance of ArgoCD to manage multiple clusters
  - This allows an admin to push 1 config and have it apply globally

- Multiple Cluster environments
    ![Multiple Environments](ArgoCD-Multiple-Enviornment.png)
  - You may also have multiple environments like Development / staging / productions
  - You can run a different instance of ArgoCD in each of these environments
    - You an use an overlay with Kustomize so that each environment gets the correct items

## Benefits of using ArgoCD

- the whole k8s config is defined as code from a git repo
- You CANNOT make changes directly to the cluster
  - ArgoCD will overwrite your changes
    ![actual-state](ArgoCD-Actual-State.png)

- You can configure ArgoCD to not override manual changes
  - This would not be recommended and only used in an emergency

- Version control
  - you can see a history of changes
  - you can see who made the change
  - you can propose a change and have others verify your work
  - easily rollback changes as needed

- Cluster disaster recovery
  - If you have a cluster that is failed
  - You can spin up a new cluster instantly

- Access control
  - You can limit access to the exact resource a dev needs.
  - Only a Sr. Dev can approve a pull request

- ArgoCD as K8s extension
  - Uses existing k8s functions
    - Uses etcd to store data
    - uses k8s controllers for monitoring and comparing actual and desired state
  - this gives ArgoCD much better visibility inside the cluster
  - You can see in real time via ArgoCD UI what is happening

## Hands on demo

- Install ArgoCD in your K8s Cluster
  - [Here are the steps](https://argo-cd.readthedocs.io/en/stable/getting_started/)

- Configure ArgoCD

## Common Terms

- CI/CD - Continuous Implementation Continuous Delivery
