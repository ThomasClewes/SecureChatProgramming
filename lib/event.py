import traceback

#it's like a callback but it doesn't require absurd syntax and
#can be extended without replacement
class Event:
    def __init__(self):
        self._handlers = set()

    def add_handler(self,handler):
        self._handlers.add(handler)

    def remove_handler(self,handler):
        if handler in self._handlers:
            self._handlers.remove(handler)

    def invoke(self,*args):
        for handler in self._handlers:
            handler(*args)
