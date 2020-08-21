# -*- coding: utf-8 -*-

import logging
import pathlib
import structlog
import traceback

from nplusone.core import exceptions


class Notifier(object):

    CONFIG_KEY = None
    ENABLED_DEFAULT = False

    @classmethod
    def is_enabled(cls, config):
        return (config.get(cls.CONFIG_KEY)
                or (cls.CONFIG_KEY not in config and cls.ENABLED_DEFAULT))

    def __init__(self, config):
        self.config = config  # pragma: no cover

    def notify(self, model, field):
        pass  # pragma: no cover


def get_relevant_frames(locals_only=True):
    stack = traceback.extract_stack()
    relevant_frames = [
        frame for frame in reversed(stack)
        if not locals_only or frame.filename.startswith(str(pathlib.Path().absolute()))
    ]
    return relevant_frames


class LogNotifier(Notifier):

    CONFIG_KEY = 'NPLUSONE_LOG'
    ENABLED_DEFAULT = True

    def __init__(self, config):
        self.logger = config.get('NPLUSONE_LOGGER', structlog.get_logger())
        self.level = config.get('NPLUSONE_LOG_LEVEL', logging.DEBUG)
        self.is_locals_only = config.get('NPLUSONE_LOCAL_STACK', True)

        self.verbose = config.get('NPLUSONE_VERBOSE', False)
        log_func_map = {
            logging.INFO: self.logger.info,
            logging.WARN: self.logger.warn,
            logging.ERROR: self.logger.error,
            logging.DEBUG: self.logger.debug,
            logging.CRITICAL: self.logger.critical,
        }
        self.log_func = log_func_map.get(self.level, logging.INFO)

    def notify(self, message):
        relevant_frames = get_relevant_frames(locals_only=self.is_locals_only)

        if len(relevant_frames) > 0:
            relevant_frame = relevant_frames[0]

            # This assumes we used structlog.get_logger to create our logger.
            log_info = {
                'filename': relevant_frame.filename,
                'line': relevant_frame.lineno,
                'name': relevant_frame.name,
            }

            if self.verbose:
                log_info['frames'] = '\n' + '\n'.join([
                    f'  {frame.filename}, {frame.lineno}, {frame.name}'
                    for frame in relevant_frames[1:]
                ])

            self.log_func(message.message, **log_info)
        else:
            self.log_func(message.message)


class ErrorNotifier(Notifier):

    CONFIG_KEY = 'NPLUSONE_RAISE'
    ENABLED_DEFAULT = False

    def __init__(self, config):
        self.error = config.get('NPLUSONE_ERROR', exceptions.NPlusOneError)
        self.is_locals_only = config.get('NPLUSONE_LOCAL_STACK', True)

    def notify(self, message):
        frames = get_relevant_frames(locals_only=self.is_locals_only)
        if len(frames) > 0:
            relevant_frame = get_relevant_frames()[0]
            raise self.error(message.message + ', ' +
                            str(relevant_frame)[len('<FrameSummary '):-1])
        else:
            raise self.error(message.message)


def init(config):
    return [
        notifier(config) for notifier in (LogNotifier, ErrorNotifier)
        if notifier.is_enabled(config)
    ]
