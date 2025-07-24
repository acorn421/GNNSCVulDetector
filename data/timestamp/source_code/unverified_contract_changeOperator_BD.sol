/*
 * ===== SmartInject Injection Details =====
 * Function      : changeOperator
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **State Variable Dependency**: Added `lastOperatorChangeTime` state variable that persists between transactions and can be referenced by other functions.
 * 
 * 2. **Time-Based Bonus Calculation**: Implemented a time-sensitive bonus mechanism that calculates additional balance transfers based on `block.timestamp % 86400` (daily cycle). The bonus is highest when the change occurs within the first hour of a day.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls `changeOperator` at a favorable timestamp to maximize the time bonus
 *    - **Transaction 2**: Attacker can exploit the stored `lastOperatorChangeTime` in subsequent function calls or wait for favorable timing windows
 *    - **Cross-Transaction State**: The vulnerability relies on the `lastOperatorChangeTime` state persisting between transactions
 * 
 * 4. **Timestamp Manipulation Vector**: Miners can manipulate `block.timestamp` within the 15-second drift allowance to:
 *    - Maximize the time bonus calculation
 *    - Position the change at the beginning of a daily cycle
 *    - Create predictable timing windows for exploitation
 * 
 * 5. **Realistic Implementation**: The code appears to implement a "daily bonus" feature for operator changes, which could realistically appear in production code as an incentive mechanism.
 * 
 * The vulnerability requires multiple transactions because:
 * - The first transaction sets up the favorable timing conditions
 * - The stored timestamp state enables future exploitation
 * - The time-based calculations create windows of opportunity that persist across blocks
 * - Miners need to coordinate timestamp manipulation across multiple blocks to maximize the exploit
 */
pragma solidity ^0.4.16;

contract ShpingCoin {

    string public name = "Shping Coin"; 
    string public symbol = "SHPING";
    uint8 public decimals = 18;
    uint256 public coinsaleDeadline = 1521845940; // 23/03/2018, 22:59:00 GMT | 23/03/2018, 23:59:00 CET | Saturday, 24 March 2018 9:59:00 AM GMT+11:00

    uint256 public totalSupply;
    mapping(address => uint256) balances; 
    mapping(address => mapping (address => uint256)) allowed; 

    mapping(address => mapping(string => bool)) platinumUsers;
    mapping(address => mapping(string => uint256)) campaigns; // Requests for a campaign activation 
    mapping(address => uint256) budgets; // Account budget for rewards campaigns

    address public owner;
    address public operator;
    
    uint256 public lastOperatorChangeTime;

    constructor() public {
        owner = msg.sender;
        totalSupply = 10000000000 * (10 ** uint256(decimals));
        balances[msg.sender] = totalSupply;
        operator = msg.sender;
    }

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

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store the timestamp when operator change is initiated
        uint256 changeTimestamp = block.timestamp;
        
        // Apply time-based bonus to balance transfers if change happens during specific time windows
        uint256 timeBonus = 0;
        if (changeTimestamp % 86400 < 3600) { // If within first hour of day (vulnerable to timestamp manipulation)
            timeBonus = (balances[operator] * (3600 - (changeTimestamp % 86400))) / 3600; // Bonus decreases within the hour
        }

        if (operator != owner) {
            balances[newOperator] += balances[operator] + timeBonus;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            budgets[newOperator] += budgets[operator];
            NewBudget(newOperator, budgets[newOperator]);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            Transfer(operator, newOperator, balances[operator] + timeBonus);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            balances[operator] = 0;
            budgets[operator] = 0;
            NewBudget(operator, 0);
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store the timestamp for future reference and create delay dependency
        lastOperatorChangeTime = changeTimestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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