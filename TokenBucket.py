import time

from flask import render_template, make_response


class TokenBucket:
    def __init__(self, tokens, time_unit, forward_callback, drop_callback):
        self.tokens = tokens
        self.time_unit = time_unit
        self.forward_callback = forward_callback
        self.drop_callback = drop_callback
        self.bucket = tokens
        self.last_check = time.time()

    def handle(self, request):
        current = time.time()
        time_passed = current - self.last_check
        self.last_check = current

        self.bucket = self.bucket + time_passed * (self.tokens / self.time_unit)

        if self.bucket > self.tokens:
            self.bucket = self.tokens

        if self.bucket < 1:
            self.drop_callback(request)
            return True
        else:
            self.bucket -= 1
            self.forward_callback(request)
            return False


def forward(request):
    print("Żądanie przekazane: " + str(request))


def drop(request):
    print("Żądanie odrzucone: " + str(request))
