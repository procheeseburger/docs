---
id: Paloalto-UserID-Upgrade
title: Paloalto UserID Upgrade
slug: /Paloalto-UserID-Upgrade
---

## Resources

- [Paloalto KB](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000CliqCAC#:~:text=To%20upgrade%20the%20User%2DID,up%20to%20a%20different%20location)

## Upgrade

- Navigate to services and stop the service User-ID Agent

![Stop Service](upgrade.png)

- Navigate to Program Files > Paloalto Networks > User-id agent.  
  - Zip the user-id agent folder and back it up to a different location.
- Log into [support.paloaltonetworks.com](https://support.paloaltonetworks.com) and download the latest User-Id Agent.
- Perform the install.
- Once the install is done, the latest agent should start running with all the configs retrieved from the previous agent.
