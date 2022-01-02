def ascii_header():
    print("""
██   ██ ██  ██████  ██   ██ ████████  ██████  ██     ██ ███████ ██████  
██   ██ ██ ██       ██   ██    ██    ██    ██ ██     ██ ██      ██   ██ 
███████ ██ ██   ███ ███████    ██    ██    ██ ██  █  ██ █████   ██████  
██   ██ ██ ██    ██ ██   ██    ██    ██    ██ ██ ███ ██ ██      ██   ██ 
██   ██ ██  ██████  ██   ██    ██     ██████   ███ ███  ███████ ██   ██ 
    """)

def help_menu():
    print("""
    \n\033[91m \tHIGHTOWER SERVER MANAGEMENT \033[0m
    
    \t| Configure the local server      | !listen <port>
    \t| Check the current settings      | !settings
    \t| List recent beacon check-ins    | !sessions
    \t| Check the help menu             | !help
    \t| Clear the terminal screen       | !clear
    
    \033[91m \tIMPLANT INTERACTION COMMANDS \033[0m
    
    \t| Issue a new tasking command     | !issue

    \t---------------------------------------------------------------------------------    
    
    \033[91m \tSUPPORTED TASK           DESCRIPTION                      CATEGORY \033[0m
    
    \t| get_processes          | List running processes         | Information Gathering 
    \t| get_drivers            | List running drivers           | Information Gathering 
    \t| get_users              | List information about users   | Information Gathering 
    \t| get_clipboard          | Get clipboard contents         | Information Gathering        
    \t| find_files             | Locate files by extension      | Interaction 
    \t| del_file               | Delete a file                  | Interaction 
    \t| kill_pid               | Kill a process by PID          | Interaction 
    \t| exec_command           | Execute a system command       | Interaction  
    \t| rev_shell              | Spawn an interactive shell     | Interaction
    \t| bsod                   | BSOD the system                | Other              
    \t| reg_persist            | Persist via the Registry       | Other             
    \t| uninstall              | Uninstall and remove artifacts | Other        
    """)
'''

1. each beacon request should be appended to an aray/list as a string 
2. while "interacting" with a session you can check the beaconing logs
3. the most recent beacon request should be parsed and displayed as a session


'''