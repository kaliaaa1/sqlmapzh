#!/usr/bin/env python

"""
Copyright (c) 2006-2023 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import difflib
import sqlite3
import threading
import time
import traceback

from lib.core.compat import WichmannHill
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import AttribDict
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapBaseException
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapSkipTargetException
from lib.core.exception import SqlmapThreadException
from lib.core.exception import SqlmapUserQuitException
from lib.core.exception import SqlmapValueException
from lib.core.settings import MAX_NUMBER_OF_THREADS
from lib.core.settings import PYVERSION

shared = AttribDict()

class _ThreadData(threading.local):
    """
    表示线程无关数据
    """

    def __init__(self):
        self.reset()

    def reset(self):
        """
        重置线程数据模型
        """

        self.disableStdOut = False
        self.hashDBCursor = None
        self.inTransaction = False
        self.lastCode = None
        self.lastComparisonPage = None
        self.lastComparisonHeaders = None
        self.lastComparisonCode = None
        self.lastComparisonRatio = None
        self.lastErrorPage = tuple()
        self.lastHTTPError = None
        self.lastRedirectMsg = None
        self.lastQueryDuration = 0
        self.lastPage = None
        self.lastRequestMsg = None
        self.lastRequestUID = 0
        self.lastRedirectURL = tuple()
        self.random = WichmannHill()
        self.resumed = False
        self.retriesCount = 0
        self.seqMatcher = difflib.SequenceMatcher(None)
        self.shared = shared
        self.technique = None
        self.validationRun = 0
        self.valueStack = []

ThreadData = _ThreadData()

def readInput(message, default=None, checkBatch=True, boolean=False):
    # It will be overwritten by original from lib.core.common
    pass

def isDigit(value):
    # It will be overwritten by original from lib.core.common
    pass

def getCurrentThreadData():
    """
    返回当前线程的本地数据
    """

    return ThreadData

def getCurrentThreadName():
    """
    返回当前线程名称
    """

    return threading.current_thread().getName()

def exceptionHandledFunction(threadFunction, silent=False):
    try:
        threadFunction()
    except KeyboardInterrupt:
        kb.threadContinue = False
        kb.threadException = True
        raise
    except Exception as ex:
        from lib.core.common import getSafeExString

        if not silent and kb.get("threadContinue") and not kb.get("multipleCtrlC") and not isinstance(ex, (SqlmapUserQuitException, SqlmapSkipTargetException)):
            errMsg = getSafeExString(ex) if isinstance(ex, SqlmapBaseException) else "%s: %s" % (type(ex).__name__, getSafeExString(ex))
            logger.error("thread %s: '%s'" % (threading.currentThread().getName(), errMsg))

            if conf.get("verbose") > 1 and not isinstance(ex, SqlmapConnectionException):
                traceback.print_exc()

def setDaemon(thread):
    # Reference: http://stackoverflow.com/questions/190010/daemon-threads-explanation
    if PYVERSION >= "2.6":
        thread.daemon = True
    else:
        thread.setDaemon(True)

def runThreads(numThreads, threadFunction, cleanupFunction=None, forwardException=True, threadChoice=False, startThreadMsg=True):
    threads = []

    def _threadFunction():
        try:
            threadFunction()
        finally:
            if conf.hashDB:
                conf.hashDB.close()

    kb.multipleCtrlC = False
    kb.threadContinue = True
    kb.threadException = False
    kb.technique = ThreadData.technique
    kb.multiThreadMode = False

    try:
        if threadChoice and conf.threads == numThreads == 1 and not (kb.injection.data and not any(_ not in (PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED) for _ in kb.injection.data)):
            while True:
                message = "请输入线程数? [Enter for %d (current)] " % numThreads
                choice = readInput(message, default=str(numThreads))
                if choice:
                    skipThreadCheck = False

                    if choice.endswith('!'):
                        choice = choice[:-1]
                        skipThreadCheck = True

                    if isDigit(choice):
                        if int(choice) > MAX_NUMBER_OF_THREADS and not skipThreadCheck:
                            errMsg = "最大使用线程数为 %d 避免潜在的连接问题" % MAX_NUMBER_OF_THREADS
                            logger.critical(errMsg)
                        else:
                            conf.threads = numThreads = int(choice)
                            break

            if numThreads == 1:
                warnMsg = "以单线程模式运行。这可能需要一段时间"
                logger.warning(warnMsg)

        if numThreads > 1:
            if startThreadMsg:
                infoMsg = "启动 %d 线程" % numThreads
                logger.info(infoMsg)
        else:
            try:
                _threadFunction()
            except (SqlmapUserQuitException, SqlmapSkipTargetException):
                pass
            finally:
                return

        kb.multiThreadMode = True

        # Start the threads
        for numThread in xrange(numThreads):
            thread = threading.Thread(target=exceptionHandledFunction, name=str(numThread), args=[_threadFunction])

            setDaemon(thread)

            try:
                thread.start()
            except Exception as ex:
                errMsg = "启动新线程时发生错误 ('%s')" % ex
                logger.critical(errMsg)
                break

            threads.append(thread)

        # And wait for them to all finish
        alive = True
        while alive:
            alive = False
            for thread in threads:
                if thread.is_alive():
                    alive = True
                    time.sleep(0.1)

    except (KeyboardInterrupt, SqlmapUserQuitException) as ex:
        print()
        kb.prependFlag = False
        kb.threadContinue = False
        kb.threadException = True

        if kb.lastCtrlCTime and (time.time() - kb.lastCtrlCTime < 1):
            kb.multipleCtrlC = True
            raise SqlmapUserQuitException("用户已中止(多次按下Ctrl+C)")

        kb.lastCtrlCTime = time.time()

        if numThreads > 1:
            logger.info("等待线程完成%s" % (" (Ctrl+C 已按下)" if isinstance(ex, KeyboardInterrupt) else ""))
        try:
            while (threading.active_count() > 1):
                pass

        except KeyboardInterrupt:
            kb.multipleCtrlC = True
            raise SqlmapThreadException("用户已中止(多次按下Ctrl+C)")

        if forwardException:
            raise

    except (SqlmapConnectionException, SqlmapValueException) as ex:
        print()
        kb.threadException = True
        logger.error("线程 %s: '%s'" % (threading.currentThread().getName(), ex))

        if conf.get("详细的") > 1 and isinstance(ex, SqlmapValueException):
            traceback.print_exc()

    except Exception as ex:
        print()

        if not kb.multipleCtrlC:
            if isinstance(ex, sqlite3.Error):
                raise
            else:
                from lib.core.common import unhandledExceptionMessage

                kb.threadException = True
                errMsg = unhandledExceptionMessage()
                logger.error("线程 %s: %s" % (threading.currentThread().getName(), errMsg))
                traceback.print_exc()

    finally:
        kb.multiThreadMode = False
        kb.threadContinue = True
        kb.threadException = False
        kb.technique = None

        for lock in kb.locks.values():
            if lock.locked():
                try:
                    lock.release()
                except:
                    pass

        if conf.get("hashDB"):
            conf.hashDB.flush(True)

        if cleanupFunction:
            cleanupFunction()