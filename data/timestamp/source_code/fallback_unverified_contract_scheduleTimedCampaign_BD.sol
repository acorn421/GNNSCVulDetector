/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedCampaign
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where campaign activation relies on block timestamp comparisons. The vulnerability is stateful and multi-transaction: 1) First transaction schedules a timed campaign with a future activation time, 2) Second transaction attempts to activate the campaign based on current block timestamp. Miners can manipulate block timestamps within certain bounds (±900 seconds typically) to either prevent legitimate campaign activations or allow premature activations. The state persists between transactions through the timedCampaigns mapping, making this a classic multi-transaction timestamp manipulation vulnerability.
 */
pragma solidity ^0.4.16;

contract ShpingCoin {

    string public name = "Shping Coin"; 
    string public symbol = "SHPING";
    uint8 public decimals = 18;
    uint256 public coinsaleDeadline = 1521845940; // 23/03/2018, 22:59:00 GMT

    uint256 public totalSupply;
    mapping(address => uint256) balances; 
    mapping(address => mapping (address => uint256)) allowed; 

    mapping(address => mapping(string => bool)) platinumUsers;
    mapping(address => mapping(string => uint256)) campaigns; // Requests for a campaign activation 
    mapping(address => uint256) budgets; // Account budget for rewards campaigns

    address public owner;
    address public operator;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These mappings need to be declared at contract level, not inside a function
    mapping(address => mapping(string => uint256)) timedCampaigns; // Stores campaign activation timestamps
    mapping(address => mapping(string => uint256)) timedCampaignBudgets; // Stores budgets for timed campaigns
    mapping(address => mapping(string => bool)) timedCampaignScheduled; // Tracks if campaign is scheduled
    // === END FALLBACK INJECTION ===

    function ShpingCoin() public {
        owner = msg.sender;
        totalSupply = 10000000000 * (10 ** uint256(decimals));
        balances[msg.sender] = totalSupply;
        operator = msg.sender;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function scheduleTimedCampaign(string campaign, uint256 budget, uint256 activationTime) public returns (bool) {
        require(budget != 0);
        require(activationTime > now);
        require(!timedCampaignScheduled[msg.sender][campaign]);
        require(balances[msg.sender] >= budgets[msg.sender]);
        require(balances[msg.sender] - budgets[msg.sender] >= budget);
        
        timedCampaigns[msg.sender][campaign] = activationTime;
        timedCampaignBudgets[msg.sender][campaign] = budget;
        timedCampaignScheduled[msg.sender][campaign] = true;
        
        TimedCampaignScheduled(msg.sender, campaign, budget, activationTime);
        return true;
    }

    function activateTimedCampaign(string campaign) public returns (bool) {
        require(timedCampaignScheduled[msg.sender][campaign]);
        require(now >= timedCampaigns[msg.sender][campaign]);
        require(balances[msg.sender] >= budgets[msg.sender]);
        require(balances[msg.sender] - budgets[msg.sender] >= timedCampaignBudgets[msg.sender][campaign]);
        
        uint256 budget = timedCampaignBudgets[msg.sender][campaign];
        budgets[msg.sender] += budget;
        
        // Clear the scheduled campaign
        timedCampaigns[msg.sender][campaign] = 0;
        timedCampaignBudgets[msg.sender][campaign] = 0;
        timedCampaignScheduled[msg.sender][campaign] = false;
        
        NewBudget(msg.sender, budgets[msg.sender]);
        TimedCampaignActivated(msg.sender, campaign, budget);
        return true;
    }

    function getTimedCampaignInfo(address account, string campaign) public constant returns (uint256, uint256, bool) {
        return (timedCampaigns[account][campaign], timedCampaignBudgets[account][campaign], timedCampaignScheduled[account][campaign]);
    }

    event TimedCampaignScheduled(address indexed account, string campaign, uint256 budget, uint256 activationTime);
    event TimedCampaignActivated(address indexed account, string campaign, uint256 budget);
    // === END FALLBACK INJECTION ===

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    modifier onlyOperator() {
        require(msg.sender == operator);
        _;
    }

    function changeOperator(address newOperator) public onlyOwner {
        require(newOperator != address(0));
        require(newOperator != operator);
        require(balances[newOperator]+balances[operator] >= balances[newOperator]);
        require(budgets[newOperator]+budgets[operator] >= budgets[newOperator]);

        if (operator != owner) {
            balances[newOperator] += balances[operator];
            budgets[newOperator] += budgets[operator];
            NewBudget(newOperator, budgets[newOperator]);
            Transfer(operator, newOperator, balances[operator]);
            balances[operator] = 0;
            budgets[operator] = 0;
            NewBudget(operator, 0);
        }
        operator = newOperator;
    }

    //Permanent platinum level

    function isPlatinumLevel(address user, string hashedID) public constant returns (bool) {
        return platinumUsers[user][hashedID];
    }

    function setPermanentPlatinumLevel(address user, string hashedID) public onlyOwner returns (bool) {
        require(!isPlatinumLevel(user, hashedID));
        platinumUsers[user][hashedID] = true;
        return true;
    }

    //Rewards campaigns
    function activateCampaign(string campaign, uint256 budget) public returns (bool) {
        require(campaigns[msg.sender][campaign] == 0);
        require(budget != 0);
        require(balances[msg.sender] >= budgets[msg.sender]);
        require(balances[msg.sender] - budgets[msg.sender] >= budget);
        campaigns[msg.sender][campaign] = budget;
        Activate(msg.sender, budget, campaign);
        return true;
    }

    function getBudget(address account) public constant returns (uint256) {
        return budgets[account];
    }

    function rejectCampaign(address account, string campaign) public onlyOperator returns (bool) {
        require(account != address(0));
        campaigns[account][campaign] = 0;
        Reject(account, campaign);
        return true;
    }

    function setBudget(address account, string campaign) public onlyOperator returns (bool) {
        require(account != address(0));
        require(campaigns[account][campaign] != 0);
        require(balances[account] >= budgets[account]);
        require(balances[account] - budgets[account] >= campaigns[account][campaign]);
        require(budgets[account] + campaigns[account][campaign] > budgets[account]);

        budgets[account] += campaigns[account][campaign];
        campaigns[account][campaign] = 0;
        NewBudget(account, budgets[account]);
        return true;
    }

    function releaseBudget(address account, uint256 budget) public onlyOperator returns (bool) {
        require(account != address(0));
        require(budget != 0);
        require(budgets[account] >= budget);
        require(balances[account] >= budget);
        require(balances[operator] + budget > balances[operator]);

        budgets[account] -= budget;
        balances[account] -= budget;
        balances[operator] += budget;
        Released(account, budget);
        NewBudget(account, budgets[account]);
        return true;
    }

    function clearBudget(address account) public onlyOperator returns (bool) {
        budgets[account] = 0;
        NewBudget(account, 0);
        return true;
    }

    event Activate(address indexed account, uint256 indexed budget, string campaign);
    event NewBudget(address indexed account, uint256 budget);
    event Reject(address indexed account, string campaign);
    event Released(address indexed account, uint256 value);

    //ERC20 interface
    function balanceOf(address account) public constant returns (uint256) {
        return balances[account];
    }

    function transfer(address to, uint256 value) public returns (bool) {
        require(msg.sender == owner || msg.sender == operator || now > coinsaleDeadline);
        require(balances[msg.sender] - budgets[msg.sender] >= value);
        require(balances[to] + value >= balances[to]);
        
        balances[msg.sender] -= value;
        balances[to] += value;
        Transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(from == owner || from == operator || msg.sender == owner || msg.sender == operator || now > coinsaleDeadline);
        require(balances[from] - budgets[from] >= value);
        require(allowed[from][msg.sender] >= value);
        require(balances[to] + value >= balances[to]);

        balances[from] -= value;
        allowed[from][msg.sender] -= value;
        balances[to] += value;
        Transfer(from, to, value);
        return true;
    }

    function approve(address spender, uint256 value) public returns (bool) {
        allowed[msg.sender][spender] = value;
        Approval(msg.sender, spender, value);
        return true;
    }

    function allowance(address account, address spender) public constant returns (uint256) {
        return allowed[account][spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
