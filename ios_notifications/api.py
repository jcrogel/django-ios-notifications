# -*- coding: utf-8 -*-
import re
import sys, os, hashlib

from django.http import HttpResponseNotAllowed, QueryDict
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
from django.contrib.auth.models import User
from django.utils.decorators import method_decorator
import httplib, urllib, json, logging

from .models import Device
from .forms import DeviceForm
from .decorators import api_authentication_required
from .http import HttpResponseNotImplemented, JSONResponse
import datetime


class BaseResource(object):
    """
    The base class for any API Resources.
    """
    allowed_methods = ('GET', 'POST', 'PUT', 'DELETE')

    @method_decorator(api_authentication_required)
    @csrf_exempt
    def route(self, request, **kwargs):
        method = request.method
        if method in self.allowed_methods:
            if hasattr(self, method.lower()):
                if method == 'PUT':
                    request.PUT = QueryDict(request.body if django.VERSION >= (1, 4) else request.raw_post_data).copy()
                return getattr(self, method.lower())(request, **kwargs)

            return HttpResponseNotImplemented()

        return HttpResponseNotAllowed(self.allowed_methods)


class PushResource(BaseResource):
    """
    The API resource for ios_notifications.models.Push.

    Allowed HTTP methods are GET, POST and PUT.
    """
    allowed_methods = ('POST')

    def post(self, request, **kwargs):
        """
        Creates a new device or updates an existing one to `is_active=True`.
        Expects two non-options POST parameters: `token` and `service`.
        """
        content = request.META.get('HTTP_CONTENT_TYPE', None)
        req_post = dict(request.POST)

        if content.startswith("application/json"):
            req_post = json.loads(request.body)

        tokens = req_post.get('tokens', None)
        service = req_post.get('service', 0)
        msg = req_post.get('message', None)
        payload = req_post.get('payload', None)
        signature = req_post.get('signature', None)
        timestamp = req_post.get('timestamp', None)
        shared_key = "AQ7YpEtTu2l6Ae2QyaTzVllQj7q9AqH"
        received_signature = hashlib.sha224(shared_key+ str(timestamp)).hexdigest()
        if (received_signature!=signature):
            return JSONResponse({"error":"Signature does not match", "success": False}, status=410)

        service_obj = None
        if isinstance(service, basestring):
            service_obj = APNService.objects.get(name=service)

        if not tokens:
            return JSONResponse({"error":"Tokens not passed", "success": False}, status=400)

        if not service_obj:
            return JSONResponse({"error":"Service not found", "success": False}, status=400)

        devices = Device.objects.filter(token__in=tokens, service=service_obj)
        if not devices:
            return JSONResponse({"error":"Devices do not exist", "success": False}, status=410)

        if not msg:
            return JSONResponse({"error":"Message is empty", "success": False}, status=412)

        notification = Notification.objects.create(message=msg, service=service_obj)
        if payload:
            if not isinstance(payload, dict):
                payload = json.loads(payload)
            notification.extra = payload
        service_obj.push_notification_to_devices(notification, devices, chunk_size=200)
        return JSONResponse({"success":True}, status=201)


class DeviceResource(BaseResource):
    """
    The API resource for ios_notifications.models.Device.

    Allowed HTTP methods are GET, POST and PUT.
    """
    allowed_methods = ('GET', 'POST', 'PUT')

    def get(self, request, **kwargs):
        """
        Returns an HTTP response with the device in serialized JSON format.
        The device token and device service are expected as the keyword arguments
        supplied by the URL.

        If the device does not exist a 404 will be raised.
        """

        device = get_object_or_404(Device, **kwargs)
        return JSONResponse(device)

    def external_post(self, address, url, data):
        json_data = json.dumps(data)
        post_data = json_data.encode('utf-8')

        headers = {"Content-type": "application/json",
            "Accept": "application/json"}
        conn = httplib.HTTPConnection(address)
        conn.request("POST", url, post_data, headers)
        response = conn.getresponse()
        ret_data = response.read()
        ret_code = response.status
        conn.close()
        return (ret_code, ret_data)

    def post(self, request, **kwargs):
        """
        Creates a new device or updates an existing one to `is_active=True`.
        Expects two non-options POST parameters: `token` and `service`.
        """

        if request.META.get("CONTENT_TYPE","application/json").find("")>-1:
             req_val = json.loads(request.body)

        token = req_val.get('token')
        service = req_val.get('service', 0)
        req_post = dict(req_val)

        if isinstance(service, basestring):
            service_obj = APNService.objects.get(name=service)
            if service_obj:
                service = service_obj.id
                req_post['service'] = service

        if token is not None:
            # Strip out any special characters that may be in the token
            token = re.sub('<|>|\s', '', token)
            req_post['token'] = token
        devices = Device.objects.filter(token=token,
                                        service__id=int(service))
        if devices.exists():
            device = devices.get()
            device.is_active = True
            device.save()
            return JSONResponse(device)
        form = DeviceForm(req_post)
        if form.is_valid():
            device = form.save(commit=False)
            device.is_active = True
            device.save()
            return JSONResponse(device, status=201)
        return JSONResponse(form.errors, status=400)

    def put(self, request, **kwargs):
        """
        Updates an existing device.

        If the device does not exist a 404 will be raised.

        The device token and device service are expected as the keyword arguments
        supplied by the URL.

        Any attributes to be updated should be supplied as parameters in the request
        body of any HTTP PUT request.
        """
        try:
            device = Device.objects.get(**kwargs)
        except Device.DoesNotExist:
            return JSONResponse({'error': 'Device with token %s and service %s does not exist' %
                                (kwargs['token'], kwargs['service__id'])}, status=400)

        if 'users' in request.PUT:
            try:
                user_ids = request.PUT.getlist('users')
                device.users.remove(*[u.id for u in device.users.all()])
                device.users.add(*User.objects.filter(id__in=user_ids))
            except (ValueError, IntegrityError) as e:
                return JSONResponse({'error': e.message}, status=400)
            del request.PUT['users']

        for key, value in request.PUT.items():
            setattr(device, key, value)
        device.save()

        return JSONResponse(device)


class Router(object):
    """
    A simple class for handling URL routes.
    """
    def __init__(self):
        self.device = DeviceResource().route
        self.push = PushResource().route

routes = Router()
