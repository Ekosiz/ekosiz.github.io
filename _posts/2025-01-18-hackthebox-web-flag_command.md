---
title: "HackTheBox: Flag Command" 
date: 2025-01-18 01:28:59 +0000
categories: [HackTheBox, Web]
tags: [api, web, developer_tool, proxy]
image:
    path: /images/hackthebox/web/flag_command/room_image.png
---

## Details
![Challenge Card](/images/hackthebox/web/flag_command/info_card.png)
[**Challenge Link**](https://app.hackthebox.com/challenges/Flag%2520Command)

---

## Summary

In this challenge, I utilized the browser’s developer tools to investigate the web application’s network activity. Through this analysis, I identified crucial API endpoints that revealed hidden command. By observing both `GET` and `POST` requests, I discovered that the endpoint `api/options` contained a secret command. This command was then submitted via a `POST` request to the `api/monitor` endpoint, which ultimately allowed me to retrieve the flag.


---

## 1. Initial Exploration

Upon visiting the website, I was greeted with a visually appealing introduction to a game that prompted me to type "start" to begin. The game presented various options, and based on my choices, it told a story and asked me to select the next option. It seemed to be a simple, interactive game with limited functionality. However, as none of the available options led directly to the flag, I decided to look deeper into the application to uncover any hidden features that might reveal the flag.

![Game image](/images/hackthebox/web/flag_command/initial_exploration.png)

---

## 2. Using Developer Tools

To dive deeper, I turned to the browser's developer tools. I opened the network tab and refreshed the page, which allowed me to monitor the requests made by the website. This was a critical step in understanding how the page works behind the scenes. An interesting GET request made to `/api/options` end point.

![Network Tab](/images/hackthebox/web/flag_command/developer_tool.png)

I manually visited this api end point and seen a list of options in JSON format. This endpoint just returns available options that user can use.

```json
{
  "allPossibleCommands": {
    "1": [
      "HEAD NORTH",
      "HEAD WEST",
      "HEAD EAST",
      "HEAD SOUTH"
    ],
    "2": [
      "GO DEEPER INTO THE FOREST",
      "FOLLOW A MYSTERIOUS PATH",
      "CLIMB A TREE",
      "TURN BACK"
    ],
    "3": [
      "EXPLORE A CAVE",
      "CROSS A RICKETY BRIDGE",
      "FOLLOW A GLOWING BUTTERFLY",
      "SET UP CAMP"
    ],
    "4": [
      "ENTER A MAGICAL PORTAL",
      "SWIM ACROSS A MYSTERIOUS LAKE",
      "FOLLOW A SINGING SQUIRREL",
      "BUILD A RAFT AND SAIL DOWNSTREAM"
    ],
    "secret": [
      "Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"
    ]
  }
}
```
The key `secret` looks something interesting to keep in mind!

---

## 3. Investigating JavaScript

Upon examining the JavaScript files present in the developer tool, I noticed that there were another API endpoint that has been utilized within the `main.js` file on the ```/static/terminal/js/main.js``` path.

```javascript
// HTTP REQUESTS
// ---------------------------------------
async function CheckMessage() {
    fetchingResponse = true;
    currentCommand = commandHistory[commandHistory.length - 1];

    if (availableOptions[currentStep].includes(currentCommand) || availableOptions['secret'].includes(currentCommand)) {
        await fetch('/api/monitor', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 'command': currentCommand })
        })
            .then((res) => res.json())
            .then(async (data) => {
                console.log(data)
                await displayLineInTerminal({ text: data.message });

                if(data.message.includes('Game over')) {
                    playerLost();
                    fetchingResponse = false;
                    return;
                }

                if(data.message.includes('HTB{')) {
                    playerWon();
                    fetchingResponse = false;

                    return;
                }

                if (currentCommand == 'HEAD NORTH') {
                    currentStep = '2';
                }
                else if (currentCommand == 'FOLLOW A MYSTERIOUS PATH') {
                    currentStep = '3'
                }
                else if (currentCommand == 'SET UP CAMP') {
                    currentStep = '4'
                }

                let lineBreak = document.createElement("br");


                beforeDiv.parentNode.insertBefore(lineBreak, beforeDiv);
                displayLineInTerminal({ text: '<span class="command">You have 4 options!</span>' })
                displayLinesInTerminal({ lines: availableOptions[currentStep] })
                fetchingResponse = false;
            });


    }
    else {
        displayLineInTerminal({ text: "You do realise its not a park where you can just play around and move around pick from options how are hard it is for you????" });
        fetchingResponse = false;
    }
}
```

It can be observed from the JavaScript code snippet that a POST request has been sent to the end point `/api/monitor` with the command that user has written. This can also be observed from the developer tools network tab after starting the game and choosing an option. 

![Network Tab Post Request](/images/hackthebox/web/flag_command/developer_tool_post_req.png)

---

## 4. Utilizing Secret Command

From investigating the game, every options can be seen in the JSON file that we observed by visiting the `/api/options` end point on the domain. However, the `secret` option is not given us to utilize it. Therefore, instead of choosing what game offers us to choose, we will write the secret option which is `Blip-blop, in a pickle with a hiccup! Shmiggity-shmack`. After submitting the command, the flag is revealed and congratulate us on winning the game.

![Flag on the web browser](/images/hackthebox/web/flag_command/flag_from_browser.png)



