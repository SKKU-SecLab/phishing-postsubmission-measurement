from selenium import webdriver
from selenium.webdriver.support.select import Select
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import StaleElementReferenceException, TimeoutException, UnexpectedAlertPresentException, NoSuchFrameException, NoAlertPresentException, ElementNotVisibleException, InvalidElementStateException
from urllib.parse import urlparse, urljoin
import json
import pprint
import datetime
import tldextract
import math
import os
import traceback
import random
import re
import logging
import copy
import time

import Classes

from selenium.webdriver.common.by import By # JP


def extract_ui_forms(driver):
    sources = []
    submits =  []
    ui_forms = []

    #toggles = driver.find_elements_by_xpath("//input") # Original JP
    toggles = driver.find_elements(By.XPATH, "//input") # New JP
    for toggle in toggles:
        try:
            input_type = toggle.get_attribute("type")
            if (not input_type) or input_type == "text":
                #in_form = toggle.find_elements_by_xpath(".//ancestor::form") # Original JP
                in_form = toggle.find_elements(By.XPATH, ".//ancestor::form") # New JP
                if not in_form:
                    xpath = driver.execute_script("return getXPath(arguments[0])", toggle)
                    sources.append( {'xpath': xpath, 'value': 'jAEkPotUI'} )
        except:
            logging.warning("UI form error")

    #toggles = driver.find_elements_by_xpath("//textarea") # Original JP
    toggles = driver.find_elements(By.XPATH, "//textarea") # New JP
    for toggle in toggles:
        try:

            #in_form = toggle.find_elements_by_xpath(".//ancestor::form") # Original JP
            in_form = toggle.find_elements(By.XPATH, ".//ancestor::form") # New JP
            if not in_form:
                xpath = driver.execute_script("return getXPath(arguments[0])", toggle)
                sources.append( {'xpath': xpath, 'value': 'jAEkPotUI'} )
        except:
            logging.warning("UI form error")


    if sources:
        # buttons = driver.find_elements_by_xpath("//button")
        buttons = driver.find_elements(By.XPATH, "//button") # New JP
        for button in buttons:
            try:
                #in_form = button.find_elements_by_xpath(".//ancestor::form")  # Original JP 
                in_form = button.find_elements(By.XPATH, ".//ancestor::form") # New JP
                if not in_form:
                    xpath = driver.execute_script("return getXPath(arguments[0])", button)
                    ui_forms.append( Classes.Ui_form(sources, xpath))
            except:
                logging.warning("UI form error")



    return ui_forms


