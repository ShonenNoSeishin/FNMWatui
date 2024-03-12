from django import forms
from django.contrib.auth.models import User
from .models import Network, Flowspec
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
import ipaddress


def validate_network(value):
    if not "/" in value:
        raise ValidationError(f"Please specify a Netmask")
    try:
        ipaddress.ip_network(value)
    except ValueError as err:
        raise ValidationError(f"The Network {value} is not a valid network") from err

class ModifyHostgroupForm(forms.Form):
    name = forms.CharField()
    description = forms.CharField()
    mapped_networks = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 5, 'cols': 40}),
        help_text="Enter IP addresses or networks separated by commas.",
        required=False
    )
    threshold_pps = forms.CharField()
    threshold_mbps = forms.CharField()
    threshold_flows = forms.CharField()
    enable_ban = forms.CharField()

class ModifyFlowspecForm(forms.Form):
    destination_prefix = forms.CharField()
    action_type = forms.CharField()
    source_prefix = forms.CharField()
    source_ports = forms.CharField()
    destination_ports = forms.CharField()
    protocols = forms.CharField()


class add_blackhole_form(forms.Form):
    blackholed_ip = forms.CharField()

class HostgroupForm(forms.Form):
    name = forms.CharField(label='Name', max_length=100)
    description = forms.CharField(
        label='Description',
        widget=forms.Textarea(attrs={'rows': 2, 'cols': 40}),
    )

class NetworkForm(forms.ModelForm):
    net = forms.CharField(
        widget=forms.TextInput(attrs={"style": "width: 100%;"}),
        label="Network (CIDR notation)",
        required=True,
        validators=[validate_network],
    )
    user = forms.ModelChoiceField(
        User.objects.all(),
        widget=forms.Select(attrs={"style": "width: 100%;"}),
        label="User",
        required=True,
    )

    # An inline class to provide additional information on the form.
    class Meta:
        fields = ("net", "user")
        # This is the association between the model and the model form
        model = Network


class FlowspecForm(forms.ModelForm):

    # An inline class to provide additional information on the form.
    class Meta:
        model = Flowspec
        fields = (
            "net",
            "name",
            "srcip",
            "srcprt",
            "dstip",
            "dstprt",
            "protocol",
            "action",
        )

    # This is the association between the model and the model form
    model = Flowspec

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user:
            self.user = user
            self.fields['net'].queryset = Network.objects.filter(user=user)


    protocol_list = [
        ("", ""),
        ("udp", "udp"),
        ("tcp", "tcp"),
        ("icmp", "icmp"),
    ]
    action_list = [
        ("discard", "discard"),
        ("accept", "accept"),
    ]

    protocol = forms.CharField(
        widget=forms.Select(choices=protocol_list, attrs={"style": "width: 100%;"}),
        label="Protocol",
        required=False,
    )
    action = forms.CharField(
        widget=forms.Select(choices=action_list, attrs={"style": "width: 100%;"}),
        label="Action",
        required=True,
    )

    net = forms.ModelChoiceField(
        Network.objects.all(),
        widget=forms.Select(attrs={"style": "width: 100%;"}),
        label="Destination Network*",
    )

    name = forms.CharField(
        widget=forms.TextInput(attrs={"style": "width: 100%;"}),
        label="Rule Name*",
        required=True,
    )
    srcip = forms.CharField(
        widget=forms.TextInput(attrs={"style": "width: 100%;"}),
        label="Source IP",
        initial="",
        required=False,
    )
    srcprt = forms.IntegerField(
        widget=forms.TextInput(attrs={"style": "width: 100%;"}),
        label="Source Port",
        required=False,
    )
    dstip = forms.CharField(
        widget=forms.TextInput(attrs={"style": "width: 100%;"}),
        label="Destination IP*",
        required=True,
    )
    dstprt = forms.IntegerField(
        widget=forms.TextInput(attrs={"style": "width: 100%;"}),
        label="Destination Port",
        required=False,
    )

    # Custom validator
    def clean(self):
        cleaned_data = super().clean()
        net = cleaned_data.get("net")
        srcip = cleaned_data.get("srcip")
        srcprt = cleaned_data.get("srcprt")
        dstip = cleaned_data.get("dstip")
        dstprt = cleaned_data.get("dstprt")
        protocol = cleaned_data.get("protocol")

        try:
            ipaddress.ip_network(dstip)
        except:
            print("not valid")
            self.add_error("dstip", ValidationError(f"{dstip} is not a valid IP"))
            return
        if not "/" in dstip:
            print("please specify netmask")
            self.add_error("dstip", ValidationError(f"Please specify a Netmask"))
            return
        if not ipaddress.ip_network(dstip).subnet_of(ipaddress.ip_network(net)):
            print("not a subnet of net")
            self.add_error(
                "dstip", ValidationError(f"{dstip} is not a subnet of {net}")
            )
            return
        if protocol == "icmp" and dstprt != None:
            print("not port with icmp allowed")
            self.add_error(
                "dstprt", ValidationError("You can't specify a port with protocol ICMP")
            )
            return
        if srcip != '':
            try:
                ipaddress.ip_network(srcip)
            except:
                print("not valid")
                self.add_error("srcip", ValidationError(f"{srcip} is not a valid IP"))
                return
            if not "/" in srcip:
                print("please specify netmask")
                self.add_error("srcip", ValidationError(f"Please specify a Netmask"))
                return
        if srcprt is None:
            self.cleaned_data["srcprt"] = -1
        if dstprt is None:
            self.cleaned_data["dstprt"] = -1


class FlowspecModifyForm(forms.ModelForm):

    # An inline class to provide additional information on the form.
    class Meta:
        model = Flowspec
        fields = (
            "net",
            "name",
            "srcip",
            "srcprt",
            "dstip",
            "dstprt",
            "protocol",
            "action",
        )

    # This is the association between the model and the model form
    model = Flowspec

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        instance = kwargs.get('instance', None)
        super().__init__(*args, **kwargs)
        if user:
            self.user = user
            self.fields['net'].queryset = Network.objects.filter(user=user)

        if instance:
            self.fields['net'].queryset = Network.objects.filter(user=instance.net.user)


    protocol_list = [
        ("", ""),
        ("udp", "udp"),
        ("tcp", "tcp"),
        ("icmp", "icmp"),
    ]
    action_list = [
        ("discard", "discard"),
        ("accept", "accept"),
    ]

    protocol = forms.CharField(
        widget=forms.Select(choices=protocol_list, attrs={"style": "width: 100%;"}),
        label="Protocol",
        required=False,
    )
    action = forms.CharField(
        widget=forms.Select(choices=action_list, attrs={"style": "width: 100%;"}),
        label="Action",
        required=True,
    )

    net = forms.ModelChoiceField(
        Network.objects.all(),
        widget=forms.Select(attrs={"style": "width: 100%;"}),
        label="Destination Network*",
    )

    name = forms.CharField(
        widget=forms.TextInput(attrs={"style": "width: 100%;"}),
        label="Rule Name*",
        required=True,
    )
    srcip = forms.CharField(
        widget=forms.TextInput(attrs={"style": "width: 100%;"}),
        label="Source IP",
        initial="",
        required=False,
    )
    srcprt = forms.IntegerField(
        widget=forms.TextInput(attrs={"style": "width: 100%;"}),
        label="Source Port",
        required=False,
    )
    dstip = forms.CharField(
        widget=forms.TextInput(attrs={"style": "width: 100%;"}),
        label="Destination IP*",
        required=True,
    )
    dstprt = forms.IntegerField(
        widget=forms.TextInput(attrs={"style": "width: 100%;"}),
        label="Destination Port",
        required=False,
    )

    # Custom validator
    def clean(self):
        cleaned_data = super().clean()
        net = cleaned_data.get("net")
        srcip = cleaned_data.get("srcip")
        srcprt = cleaned_data.get("srcprt")
        dstip = cleaned_data.get("dstip")
        dstprt = cleaned_data.get("dstprt")
        protocol = cleaned_data.get("protocol")

        try:
            ipaddress.ip_network(dstip)
        except:
            print("not valid")
            self.add_error("dstip", ValidationError(f"{dstip} is not a valid IP"))
            return
        if not "/" in dstip:
            print("please specify netmask")
            self.add_error("dstip", ValidationError(f"Please specify a Netmask"))
            return
        if not ipaddress.ip_network(dstip).subnet_of(ipaddress.ip_network(net)):
            print("not a subnet of net")
            self.add_error(
                "dstip", ValidationError(f"{dstip} is not a subnet of {net}")
            )
            return
        if protocol == "icmp" and dstprt != None:
            print("not port with icmp allowed")
            self.add_error(
                "dstprt", ValidationError("You can't specify a port with protocol ICMP")
            )
            return
        if srcip != '':
            try:
                ipaddress.ip_network(srcip)
            except:
                print("not valid")
                self.add_error("srcip", ValidationError(f"{srcip} is not a valid IP"))
                return
            if not "/" in srcip:
                print("please specify netmask")
                self.add_error("srcip", ValidationError(f"Please specify a Netmask"))
                return
        if srcprt is None:
            self.cleaned_data["srcprt"] = -1
        if dstprt is None:
            self.cleaned_data["dstprt"] = -1




class User(forms.ModelForm):
    username = forms.CharField(max_length=10, widget=forms.TextInput)
    password = forms.CharField(widget=forms.PasswordInput)
