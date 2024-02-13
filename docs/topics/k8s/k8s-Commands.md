# K8s Commands

## COMMANDS

### Create

    - kubectl create -f pod-definition.yml (create a pod based on the yml file)
    - kubectl create -f file.yml --record (will record changes)
    - kubectl create namespace "name" (will create a new namespace)
    - kubectl create job "name" --image="image" "command"
    - kubectl create cronjob "name" --image="image" "command"
  
### Delete

    - kubectl delete "kind" "name" (delete the kind of item)   
    - kubectl delete --all "kind" (delete all of the kind)

### Describe

    - kubectl describe pod "pod name" (describe the pod)

### Edit

    - kubectl edit "kind" "name" (Edit the kind of item)
  
### Explain

    - kubectl explain "kind"

### Get

    - kubectl get pods (List pods in current namespace)   
    - kubectl get pods -o wide (Lists pods with more detail)
    - kubectl get pods --show-labels (shows the labels)

### label

    - kubectl label pods "name" "key=value" (this will label a pod)

### Replace

    - kubectl replace -f "filename.yml" (replace the current running item)

### Rollout

    - kubectl rollout status deployment/"name" (shows the history of rollouts)
    - kubectl rollout history deployment/"name" (shows you the rollout history)
    - kubectl rollout undo deployment/"name" (rolls back to previous version)
  
### Run

    - kubectl run "name" --image="image"  (create a pod with a name and specific image)
    - kubectl run "name" --image="image" --dry-run=client -o yaml (give the yaml output)
    - kubectl run "name" --image="image" --dry-run=client -o yaml > pod.yaml (give the yaml output in a file)
  
### Scale

    - kubectl scale --replicas="#" -f "filename.yml" (This will scale up replicaset but it wont adjust the yaml file)
    - kubectl scale replicaset "name" --replicas="#" (This will scale up the replicaset)

