# -*- coding:utf-8 -*-
################################################################################
# Copyright (C) 2018
# Adam Russell <adam[at]thecliguy[dot]co[dot]uk> 
# https://www.thecliguy.co.uk
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
################################################################################
# format_bridge_bot_output
#
# A bridge bot relays messages between IRC and other chat networks such as Slack 
# and Discord. Since messages from the users of such networks are sent from the 
# bot, the name of the sender is contained within the message text, the format 
# of which is up to the admin of the bot.
#
# This script intercepts messages before WeeChat displays them and does the 
# following:
#  - Checks whether there is an option group which matches the senders nick and
#    the server and channel for which the message was bound.
#  - If a match is found then the group's regex option is applied to the message.
#  - If the regex matches then the network, nick and text are extracted and the 
#    message is altered so that it is displayed as though it came from a native 
#    IRC user.
#
# In the example below three users are conversing, two of which are using Slack
# and one Discord. The name of the bridge bot is Kilroy. The bot's admin has 
# configured the message text to be formatted as follows: (network) <nick> Message
#
# TIME        NICK      MESSAGE
# ----        ----      -------
# 12:07:01    Kilroy    (slack) <Barry> Good afternoon.
# 12:08:20    Kilroy    (slack) <Charles> Hello Barry.
# 12:08:43    Kilroy    (discord) <Nigel> Hi Barry.
#
# Using this script, the messages would be intercepted and amended to appear as
# though Barry, Charles and Nigel are native IRC users, EG:
#
# TIME        NICK       MESSAGE
# -----       ----       -------
# 12:07:01    Barry      [slack] Good afternoon.
# 12:08:20    Charles    [slack] Hello Barry.
# 12:08:43    Nigel      [discord] Hi Barry.
#
# Since WeeChat now treats the messages as though they came from native IRC 
# users it'll apply different colours to nicks (as per your WeeChat 
# configuration) which (in my opinion) makes it easier to follow a conversation.
#
################################################################################
# Settings / Options:
#
# This script groups script options as follows:
#   <optgroup>.bot_nicks
#   <optgroup>.channel
#   <optgroup>.nick_display_max_length
#   <optgroup>.regex
#   <optgroup>.server
#
# Options can be added and removed using WeeChat's '/set' and '/unset' commands,
# EG: 
#  /set plugins.var.python.format_bridge_bot_output.MyGroup.channel #foobar
#  /unset plugins.var.python.format_bridge_bot_output.MyGroup.channel
#
# Alternatively, this script provides some commands for adding and removing 
# options.
#
# To add server, channel, bot_nicks and nick_display_max_length to a group using
# a single command: 
#   /format_bridge_bot_output_add-server-channel-botnicks-nicklength
#
# To add a regex to a group:
#   /format_bridge_bot_output_add-regex
#
# To remove all the options for a group: 
#   /format_bridge_bot_output_remove-group-options
#
# To view all current script options:
#  /format_bridge_bot_output_print-debug
#
# For example usage of all the commands above, simply type '/help' followed by 
# the command name, EG:
#  /help format_bridge_bot_output_add-regex
#
################################################################################
# Action Messages:
#
# When a user sends an action message in IRC it is typically done using the 
# '/me' command, EG '/me sighs'.
# The 'text' element of such messages starts with "\x01ACTION" and end with 
# "\x01", see https://modern.ircdocs.horse/ctcp.html#action
# "\x01" is a control code denoting Start of Heading, see 
# https://en.wikipedia.org/wiki/C0_and_C1_control_codes#SOH.
#
# Chat services like Slack and Discord may implement a means of performing
# action messages. It is up to the bridge bot to correctly interpret such 
# messages and format them as above so that an IRC client can render them as
# action messages.
#
# In order to intercept action messages, your regex should start with a named
# capture group 'action' as follows: (?P<action>(?:^[\x01]ACTION |^))
#
# NB: In order to check for the presence of the Start of Heading control
# character using Python's 're.match' method it must be placed within square 
# brackets: [\x01].
#
################################################################################
# Change Log:
#
# 0.4.0 10/11/18 (AR)
#   * Related script options are now grouped as follows: <optgroup>.<OPTION-NAME>
#
#     When a message is received, the server, channel and nick from which it was
#     sent are checked against all groups.
#     If:
#       * No match is returned, the message is unaltered.
#       * One match is returned, the regex of the matching group is applied.
#         If the regex returns a result then the message must have emanated from
#         a bridge bot and is thus modified accordingly. Else, the message is
#         unaltered.
#       * More than one match is returned, an error is logged to the WeeChat
#         core buffer and the message is unaltered.
#
#   * Added four new hook commands:
#       1. <SCRIPT_NAME>_add-server-channel-botnicks-nicklength
#       2. <SCRIPT_NAME>_add-regex
#       3. <SCRIPT_NAME>_remove-group-options
#       4. <SCRIPT_NAME>_print-debug
#
# 0.3.0 - 14/10/18 (AR)
#   * Updated the default regex to accommodate action messages.
#
# 0.2.0 - 16/07/18 (AR)
#   * Removed the 2nd and 3rd default regex values, replaced with empty string.
#     Added an empty string check to 'msg_cb' to accommodate this change.
#   * The wrong hook was being used to detect config changes. Was using 
#     'w.hook_modifier', changed to 'w.hook_config'.
#   * Added two new config items; servers and channels, both of which accept
#     a space delimited list of strings. If the message received did not 
#     originate from a specified channel on a specified server then 'msg_cb'
#     simply returns an unaltered message.
#
# 0.1.0 - 15/07/18 (AR)
#   * This script started life as 'weechat_bot2human.py' (version 0.1.1) from  
#     the scripts repository of the TUNA (Tsinghua University TUNA Association) 
#     organization on Github: https://github.com/tuna/scripts.
#
#     The original script did not contain a licence notice in the header, 
#     however the value of the constant 'SCRIPT_LICENSE' was 'GPLv3'. I have 
#     therefore added a licence notice in accordance with the guidance on
#     gnu.org (https://www.gnu.org/licenses/gpl-howto.html) for GPL version 3 or 
#     later.
#
#     Furthermore, the original script lacked a copyright notice, however the
#     author's were referenced in the constant 'SCRIPT_AUTHOR' as 'Justin Wong & 
#     Hexchain'.
#
#     The script has been renamed to format_bridge_bot_output.
#
#   * Added support for an additional regex named capture group called 'network'.
#   * Reformatted the message output to include 'network'.
#   * Nicks greater than X characters are truncated with an ellipsis appended.
#   * Zero-width space(s) are now removed from nicks.
#
################################################################################

import weechat as w
import re
import sys

SCRIPT_NAME = "format_bridge_bot_output"
SCRIPT_AUTHOR = "Adam Russell (https://www.thecliguy.co.uk)"
SCRIPT_DESC = "Formats messages received from a bridge bot to appear as though they came from an IRC user."
SETTINGS_PREFIX = "plugins.var.python.{}.".format(SCRIPT_NAME)
SCRIPT_VERSION = "0.4.0"
SCRIPT_LICENSE = "GPLv3"

PY2 = sys.version_info < (3,)

settings_lst = []

def parse_config():   
    # Clear settings_lst
    del settings_lst[:]
    
    infolist = w.infolist_get("option", "", SETTINGS_PREFIX + "*")
    
    optiongroups_lst = []
    
    if infolist:
        while w.infolist_next(infolist):
            name = w.infolist_string(infolist, "option_name")
            name = name.replace("python." + SCRIPT_NAME + ".", "")
            GroupName = name.split(".")[0]
            optiongroups_lst.append(GroupName)
                              
    w.infolist_free(infolist)
    
    # Get unique option group names
    optiongroups_lst = list(set(optiongroups_lst))
    
    import collections
    
    for GroupName in optiongroups_lst:
        settings_namedtuple = collections.namedtuple('settings_namedtuple', 'name server channel bot_nicks nick_display_max_length regex')
                    
        obj = settings_namedtuple(
            name = GroupName, 
            server = w.config_get_plugin(GroupName + ".server"), 
            channel = w.config_get_plugin(GroupName + ".channel"),
            bot_nicks = w.config_get_plugin(GroupName + ".bot_nicks"),
            nick_display_max_length = w.config_get_plugin(GroupName + ".nick_display_max_length"),
            regex = w.config_get_plugin(GroupName + ".regex")
        )     
        
        settings_lst.append(obj)
    
    ####for x in settings_lst:
    ####    w.prnt("", "ZZZ: " + str(x))


def config_cb(data, option, value):
    #### w.prnt("", "config_cb")
    #### w.prnt("", "data: " + data)
    #### w.prnt("", "option: " + option)
    #### w.prnt("", "value: " + value)
    
    # NB: If value = null this may be because the option has been unset (removed).
    
    GroupNameAndOptionName = option.replace(SETTINGS_PREFIX, "")
    GroupName = GroupNameAndOptionName.split(".")[0]
    OptionName = GroupNameAndOptionName.split(".")[1]
    
    # Prevent a duplicate option group from being added to the settings list.
    # Use list comprehension to filter out tuples where the name matches the
    # option group name.
    tmplist = [item for item in settings_lst if item.name != GroupName]
    
    import collections
    
    settings_namedtuple = collections.namedtuple('settings_namedtuple', 'name server channel bot_nicks nick_display_max_length regex')
    
    obj = settings_namedtuple(
        name = GroupName, 
        server = w.config_get_plugin(GroupName + ".server"), 
        channel = w.config_get_plugin(GroupName + ".channel"),
        bot_nicks = w.config_get_plugin(GroupName + ".bot_nicks"),
        nick_display_max_length = w.config_get_plugin(GroupName + ".nick_display_max_length"),
        regex = w.config_get_plugin(GroupName + ".regex")
    )

    # If all obj properties are null/empty then don't bother adding to the list
    if not obj.server and not obj.channel and not obj.bot_nicks and not obj.regex:
        pass
    else:
        tmplist.append(obj)
    
    # Replace all elements in the existing settings list object.
    # https://stackoverflow.com/questions/26233935/what-is-the-correct-way-to-reassign-a-list-in-python
    settings_lst[:] = tmplist
    
    ####w.prnt("", "Group Name: " + GroupName + ", Option Name: " + OptionName + ", Value: " + value)
    
    return w.WEECHAT_RC_OK

    
def add_server_channel_botnicks_nicklength(data, buffer, argList):
    intMaxArgs = 5
    split_args = argList.split(" ")
    num_of_args = len(split_args)
    
    if not argList:
        #print_help()
        w.prnt("", w.prefix("error") + "No arguments supplied.")
        return w.WEECHAT_RC_ERROR
        
    if num_of_args <> intMaxArgs:
        #print_help()
        w.prnt("", w.prefix("error") + "Wrong number of arguments. Supplied: " + str(num_of_args) + ", required: " + str(intMaxArgs) +".")
        return w.WEECHAT_RC_ERROR
    
    GroupName = split_args[0]
    server = split_args[1]
    channel = split_args[2]
    bot_nicks = split_args[3]
    nick_display_max_length = split_args[4]
    
    ####w.prnt("", "Group Name: " + GroupName)
    ####w.prnt("", "Server: " + server)
    ####w.prnt("", "Channel: " + channel)
    ####w.prnt("", "Bot_Nicks: " + bot_nicks)
    ####w.prnt("", "Nick_Display_Max_Length: " + nick_display_max_length)
    ####w.prnt("", "Option count: " + str(num_of_args))
    
    w.config_set_plugin(GroupName + ".server", server)
    w.config_set_plugin(GroupName + ".channel", channel)
    w.config_set_plugin(GroupName + ".bot_nicks", bot_nicks)
    w.config_set_plugin(GroupName + ".nick_display_max_length", nick_display_max_length)
    
    return w.WEECHAT_RC_OK
   

def add_regex(data, buffer, argList):
    intMaxArgs = 2
    split_args = argList.split(" ", 1)
    num_of_args = len(split_args)
    
    if not argList:
        #print_help()
        w.prnt("", w.prefix("error") + "No arguments supplied.")
        return w.WEECHAT_RC_ERROR
        
    if num_of_args <> intMaxArgs:
        #print_help()
        w.prnt("", w.prefix("error") + "Wrong number of arguments. Supplied: " + str(num_of_args) + ", required: " + str(intMaxArgs) +".")
        return w.WEECHAT_RC_ERROR
    
    GroupName = split_args[0]
    regex = split_args[1]
    
    ####w.prnt("", "Group Name: " + GroupName)
    ####w.prnt("", "Regex: " + regex)
    ####w.prnt("", "Option count: " + str(num_of_args))
    
    w.config_set_plugin(GroupName + ".regex", regex)
    
    return w.WEECHAT_RC_OK
   

def remove_group_options(data, buffer, argList):
    intMaxArgs = 1
    split_args = argList.split(" ")
    num_of_args = len(split_args)
    
    if not argList:
        #print_help()
        w.prnt("", w.prefix("error") + "No arguments supplied.")
        return w.WEECHAT_RC_ERROR
        
    if num_of_args <> intMaxArgs:
        #print_help()
        w.prnt("", w.prefix("error") + "Wrong number of arguments. Supplied: " + str(num_of_args) + ", required: " + intMaxArgs + ".")
        return w.WEECHAT_RC_ERROR
    
    GroupName = split_args[0]
    
    infolist = w.infolist_get("option", "", SETTINGS_PREFIX + GroupName + ".*")

    counter = 0
    
    if infolist:
        while w.infolist_next(infolist):
            name = w.infolist_string(infolist, "option_name")
            name = name.replace("python." + SCRIPT_NAME + ".", "")
            w.prnt("", "Removing option: " + name)
            w.config_unset_plugin(name)
            counter += 1

    w.infolist_free(infolist)
            
    if counter == 0:
        w.prnt("", w.prefix("error") + "No group name found called '" + GroupName + "'.")
    
    return w.WEECHAT_RC_OK


def print_debug(data, buffer, argList):
    # Output the contents of the list.
    for x in settings_lst:
        w.prnt("", "----------------------------------------------------------")
        w.prnt("", "Options Group Name: " + str(x.name))
        w.prnt("", "  * server: " + str(x.server))
        w.prnt("", "  * channel: " + str(x.channel))
        w.prnt("", "  * bot_nicks: " + str(x.bot_nicks))
        w.prnt("", "  * nick_display_max_length: " + str(x.nick_display_max_length))
        w.prnt("", "  * regex: " + str(x.regex))
     
    w.prnt("", "----------------------------------------------------------")
     
    return w.WEECHAT_RC_OK
    

def msg_cb(data, modifier, modifier_data, string):
    parsed = w.info_get_hashtable("irc_message_parse", {'message': string})
        
    # Filter using list comprehension.
    # NB: modifier_data contains the server name.
    #
    # 07/11/18: Whitespace at the beginning and end of a nick within 
    # bot_nicks is stripped, used this as a reference: 
    # https://python-forum.io/Thread-Best-way-to-strip-after-split
    result = [item for item in settings_lst if item.server.strip() == modifier_data and item.channel.strip() == parsed['channel'] and parsed['nick'] in [s.strip() for s in item.bot_nicks.split(',')]]
    
    resultcount = len(result)
    if resultcount == 0:
        return string
    elif resultcount > 1:
        w.prnt("", w.prefix("error") + SCRIPT_NAME + ": More than one script option matched the following; server=" + modifier_data + ", channel=" + parsed['channel'] + ", nick=" + parsed['nick'] + ". Result count: " + str(resultcount) + ". Results: " + str(result))
        return string    
    
    bot = parsed['nick']
    
    for res in result:
        regularexp = re.compile(res.regex)
        # NB: Weechat stores all script options as strings. Therefore we need to
        # convert 'nick_display_max_length' to an integer.
        if res.nick_display_max_length:
            intNickMaxLength = int(res.nick_display_max_length)
        else:
            intNickMaxLength = 0
 
    # If the value of the regex is an empty string then skip it.
    if not regularexp.pattern:
        return string
    
    m = regularexp.match(parsed['text'])
    if not m:
        return string
    
    network, nick, text = m.group('network'), m.group('nick'), m.group('text')
    
    # Preventing unwanted @mentions
    # =============================
    # Consider the following... A user has an account in an IRC channel and its
    # bridged Slack channel. If he says something in Slack it would trigger a 
    # mention in his IRC client. In order to prevent this, the bot must relay
    # the nick with some alteration. One such method is to place a zero-width 
    # space in the nick.
    #
    # This script renders the need for the ZWSP superfluous and thus it is 
    # removed.
    #
    # In a future version I may make this a configurable option rather than
    # having it hard-coded.
    if PY2:
        ZeroWidthSpace = (u"\u200b").encode("utf-8")
    else:
        ZeroWidthSpace = u'\u200b'
    
    nick = nick.replace(ZeroWidthSpace, "")
    
    # The width of Weechat's 'prefix line' dynamically expands to accommodate
    # the longest item within it. The more space that is occupied by the prefix 
    # line, the less space there is for the message line (where message text 
    # is displayed).
    # https://www.weechat.org/files/doc/stable/weechat_user.en.html#lines_format
    #
    # The prefix line typically contains the nick of the message sender.
    # A character limit is imposed on nick in order to prevent the prefix
    # line from dominating the screen real estate.
    #
    # NB: At the time of writing (15-Oct-18), Slack permits a nick of up to
    # 80 characters.
    #
    # If a nick exceeds the maximum length specified then it is truncated
    # with an ellipsis as the last character.
    
    if intNickMaxLength == 0:
        nickformatted = nick
    else:
        if len(nick) > intNickMaxLength:
            if PY2:
                ellipsis = (u"\u2026").encode("utf-8")
            else:
                ellipsis = u'\u2026'
        
            nickformatted = nick[0:intNickMaxLength] + ellipsis
        else:
            nickformatted = nick
    
    # A nick cannot contain a space. If it does then Weechat appears to 
    # treat what follows the space as a "command", this appears in the 
    # channel's 'server buffer'. EG the following is from a Slack user 
    # with a space is his name called 'Barry Rocks' (IP address obfuscated):
    #    20:00:00 =!= | irc: command "Rocks!~Barry" not found:
    #    20:00:00 =!= | :Barry Rocks!~Barry Rocks@1.2.3.4 PRIVMSG #foobar [slack]  Test message.    
    nickformatted = ''.join(nickformatted.split())

    text = "[" + network + "] " + text
    parsed['text'] = text
    parsed['host'] = parsed['host'].replace(bot, nickformatted)
    
    return ":{host} {command} {channel} {text}".format(**parsed)


if __name__ == '__main__':
    w.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
               SCRIPT_DESC, "", "")

    parse_config()
    
    w.hook_modifier("irc_in_privmsg", "msg_cb", "")
    w.hook_config(SETTINGS_PREFIX + "*", "config_cb", "")
            
    w.hook_command(
        SCRIPT_NAME + "_add-server-channel-botnicks-nicklength", 
        "Adds the server, channel, bot nick(s) and nick length for the specified group.", 
        "<group_name> <server> <channel> <bot_nicks> <nick_length>", 
        "group_name: The name of the group under which the options will reside.\n"
        "server: The internal server name used by WeeChat. To obtain a list of server names, use the WeeChat command '/server list'.\n"
        "channel: The channel name.\n"
        "bot_nicks: The bridge bot nick(s). Multiple nicks can be specified using a comma separated list. \n"
        "nick_length: The maximum number of characters to be displayed for nicks of a non-IRC users. Nick lengths greater than the specified value are truncated with an ellipsis appended. \n\n"
        "Example usage:\n/" + SCRIPT_NAME + "_add-server-channel-botnicks-nicklength" + " MyGroup GroovyIRC #foobar Kilroy,SonOfKilroy 20",
        "", 
        "add_server_channel_botnicks_nicklength", 
        ""
    )
    
    w.hook_command(
        SCRIPT_NAME + "_add-regex", 
        "Adds a regular expression to the specified group for extracting content "
        "from messages relayed by a bridge bot.\n\n"
        "The regex must contain the following named capture groups:\n"
        "  * action: For when a user sends an action message (typically done using '/me', EG '/me sighs')\n"
        "  * network: The external networks bridged to IRC by the bot, EG Slack or Discord.\n"
        "  * nick: The nick of the sender (not the nick of the bot)\n"
        "  * text: The message text.\n", 
        "<group_name> <regex>", 
        "group_name: The name of the group under which the options will reside.\n"
        "regex: The Regular expression. \n\n"
        "Example usage:\n/" + SCRIPT_NAME + "_add-regex" + " MyGroup (?P<action>(?:^[\x01]ACTION |^))\((?P<network>(?:slack|discord))\) <(?P<nick>.+?)> (?P<text>.*)",
        "", 
        "add_regex", 
        ""
    )
    
    w.hook_command(
        SCRIPT_NAME + "_remove-group-options", 
        "Removes all options for the specified group.", 
        "<group_name>", 
        "group_name: The name of the group under which the options you wish to remove reside.\n\n"
        "Example usage:\n/" + SCRIPT_NAME + "_remove-group-options" + " MyGroup",        
        "", 
        "remove_group_options", 
        ""
    )

    w.hook_command(
        SCRIPT_NAME + "_print-debug", 
        "Prints debug info.", 
        "", 
        "", 
        "", 
        "print_debug", 
        ""
    )
    
# vim: ts=4 sw=4 sts=4 expandtab
