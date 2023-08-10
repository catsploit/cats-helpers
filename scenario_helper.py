#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
import helper
from helper import log_debug,log_info,set_progress

from pyperplan import grounding, task
from pyperplan.pddl import parser
from pyperplan.search import searchspace

from collections import deque
import re

def _breadth_first_search(planning_task: task.Task):
        """
        Searches for a plan on the given task using breadth first search and
        duplicate detection.
        @param planning_task: The planning task to solve.
        @return: The solution as a list of operators or None if the task is
        unsolvable.
        """
        
        # fifo-queue storing the nodes which are next to explore
        queue: deque[searchspace.SearchNode] = deque()
        queue.append(searchspace.make_root_node(planning_task.initial_state))
        # set storing the explored nodes, used for duplicate detection
        closed = {planning_task.initial_state}
        while queue:
            node = queue.popleft()

            # exploring the node or if it is a goal node extracting the plan
            if planning_task.goal_reached(node.state):
                # if route is found, yield and find other solutions
                yield node.extract_solution()
                continue

            for operator, successor_state in planning_task.get_successor_states(
                node.state
            ):
                # duplicate detection
                visited = node
                while visited is not None:
                    if successor_state == visited.state:
                        fduplicated = True
                        break
                    visited = visited.parent
                else:
                    fduplicated = False

                if fduplicated == False:
                    queue.append(
                        searchspace.make_child_node(node, operator, successor_state)
                    )
                    # remember the successor state
                    closed.add(successor_state)
        
        return None

def path_solver(
        problem_pddl_filepath: str,
        domain_pddl_filepath: str,
        max_scenarios:int
    ) -> str:
        """
        Parameters
        --------
        problem_pddl_path:
            problem PDDL file path
        domain_pddl_path:
            domain PDDL file path

        Returns
        --------
        attack_path_pddl: list
            Attack path result (PDDL file)
        """

        
        log_debug("Start PDDL Parser")
        pddlParser = parser.Parser(domain_pddl_filepath, problem_pddl_filepath)
        log_debug("Finish PDDL Parser")      
        log_debug("Start Domain Parse")
        dom = pddlParser.parse_domain()
        log_debug("Finish Domain Parse")
        
        log_debug("Start Problem Parse")
        prob = pddlParser.parse_problem(dom)
        log_debug("Finish Problem Parse")
        
        log_debug("Start PDDL Parse")
        tsk: task.Task = grounding.ground(prob)
        attack_path_pddl = []
        path_list = []
        path_count = 0
        for sol in _breadth_first_search(tsk):
            path_list.append(str(sol))
            path_count += 1
            # if number of path reachs max_count, break this loop.
            if path_count == max_scenarios:
                break
        set_progress(50)
        for path in path_list:
            pattern = re.compile(r"<.*?>")
            match = re.findall(pattern, path)
            attack_path_pddl.append(match)
            
        log_debug("Finish PDDL Parse")
        
        return attack_path_pddl
    
    
def main(params):
    rval = dict()
    log_info("STARTED: args=%s", params)
    # Extract parameters from dict
    problem_pddl_filepath = params["problem_pddl_filepath"]
    domain_pddl_filepath = params["domain_pddl_filepath"]
    max_scenarios = params["max_scenarios"]
    # Call path solver
    log_info("Start searching attack path.")
    result = path_solver(problem_pddl_filepath, domain_pddl_filepath, max_scenarios)
    
    rval["path_result"] = result
    
    set_progress(100)
    
    log_info("Searching attack path is compleated.")
    
    return rval

if __name__=="__main__":
    helper.start(main)
    