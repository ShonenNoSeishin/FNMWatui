from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from django.core.validators import MaxValueValidator, MinValueValidator


class Network(models.Model):
    id = models.IntegerField(primary_key=True)  # primary keys are required by Django
    net = models.CharField(max_length=150)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="networks")

    class Meta:
        unique_together = ["net", "user"]

    def __str__(self):
        return self.net


class Flowspec(models.Model):
    id = models.IntegerField(primary_key=True)  # primary keys are required by Django
    name = models.CharField(max_length=10)
    srcip = models.CharField(max_length=50, blank=True)
    srcprt = models.IntegerField(blank=True, default=-1)
    dstip = models.CharField(max_length=50)
    dstprt = models.IntegerField(blank=True, default=-1)
    protocol = models.CharField(max_length=10, blank=True)
    action = models.CharField(max_length=10)
    active = models.BooleanField(default=False)
    net = models.ForeignKey(Network, on_delete=models.CASCADE, related_name="flowspecs")

    class Meta:
        unique_together = ["net", "srcip", "srcprt", "dstip", "dstprt", "protocol"]

    def __str__(self):
        return self.name
