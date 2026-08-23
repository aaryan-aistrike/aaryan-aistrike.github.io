---
layout: default
title: "Detections"
permalink: /detections/
---

# Research

## Detections

{% for detection in site.detections %}
- [{{ detection.title }}]({{ detection.url }})
{% endfor %}

## Threat Actor Profiles

{% for actor in site.actors %}
- [{{ actor.title }}]({{ actor.url }})
{% endfor %}

✍️ *This page will keep growing as I publish more research and detection case studies.*

