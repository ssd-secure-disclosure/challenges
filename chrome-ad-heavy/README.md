# TyphoonCon 2021 Chrome Ad-Heavy Bypass Challenge
# We will be accepting multiple submission, each eligible up to $15,000 USD in rewards.
 
## Introduction
During July 2021, SSD Secure Disclosure hosted TyphoonCon 2021 Capture the flag: a four-day competition, with specially crafted challenges alongside fantastic prizes all focused on reverse engineering and vulnerability research.
 
Feedback received for the Chrome challenge posted in the CTF, made us realize that Chrome vulnerabilities and bypasses could use some more exposure. This more focused task will hopefully encourage people to study the Chrome browser and solve parts of the challenge presented. 

*Note that the challenge below is not vulnerability-based, but meant to test your knowledge of how Chrome inner workings and its internal mechanisms.*

## Technical Details
The following is a challenge to discover a bypass for one of Chrome’s newest features:

As part of Chrome 85, Google released a feature dubbed: ‘Heavy Ad Intervention’. This feature’s goal is to stop the execution of ads that consume too much CPU or network bandwidth without the user’s consent – more information about Ad Tagging can be found in ‘Handling Heavy Ad Interventions’ at developers.google.com

The following files create a heavy-ad that Chrome will kill (a few seconds after it opens the page).  The successful solution, should provide a script that is inserted with the ad and allows the ad to run regardless of the  heavy-ad restrictions.

Four files are provided:
1) index.html – the main site users visit
2) gads.js – the file that adds the ‘advertisement’
3) adunit.html – The heavy-ad
4) big.bin – a heavy file that the ad should try to download to simulate heavy traffic.

## Objective
The participants are expected to modify the adunit.html file so that it will exceed (by downloading big.bin) the amount of network usage and the ad will not be removed by Chrome.

In essence, if you are able to download big.bin and still keep the ad running, you have bypassed the Chrome heavy-ad intervention mechanism and solved the challenge.

## Testing the bypass
* Use https://heavy-ads.glitch.me , which loads a given iframe inside an ad tagged frame.