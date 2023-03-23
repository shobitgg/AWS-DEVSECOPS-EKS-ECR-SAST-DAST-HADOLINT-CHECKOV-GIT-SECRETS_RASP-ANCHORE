NODE_ROLE_NAME="searce-terraform-eks-eks-nodegroup-role"

deploy: deploy-fluent-bit deploy-falco

deploy-fluent-bit:
	-aws iam create-policy --policy-name devsecops-eks-CloudWatchLogs --policy-document file://./fluent-bit/aws/iam_role_policy.json
	aws iam attach-role-policy --role-name $(NODE_ROLE_NAME) --policy-arn `aws iam list-policies | jq -r '.[][] | select(.PolicyName == "devsecops-eks-CloudWatchLogs") | .Arn'`
	kubectl apply -f fluent-bit/kubernetes/

deploy-falco:
    helm repo add falcosecurity https://falcosecurity.github.io/charts
	helm repo update
	helm install falco --set falco.jsonOutput=true falcosecurity/falco

clean: clean-fluent-bit clean-falco

clean-fluent-bit:
	kubectl delete -f fluent-bit/kubernetes/

clean-falco:
	helm del --purge falco
