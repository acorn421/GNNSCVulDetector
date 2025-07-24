/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Added an external call to recipient contracts after balance updates but before the Transfer event. This creates a classic reentrancy vulnerability where the recipient can call back into the contract during the transfer, with balances already updated but the transaction not yet complete. The vulnerability is stateful and multi-transaction because:
 * 
 * 1. **Multi-Transaction Exploitation**: The attack requires multiple transactions:
 *    - Transaction 1: Initial transfer to malicious contract triggers callback
 *    - Transaction 2+: Malicious contract reenters transfer() during callback with updated balances
 *    - Each reentrant call can transfer more tokens using the already-updated balance state
 *    - Multiple rounds needed to drain significant amounts due to balance checks
 * 
 * 2. **State Dependency**: The vulnerability relies on persistent state changes:
 *    - balances[msg.sender] and balances[to] are updated before external call
 *    - Reentrant calls see these updated balances and can exploit them
 *    - The budgets mapping provides additional state complexity across transactions
 *    - Each successful reentrant transfer updates state for subsequent exploits
 * 
 * 3. **Realistic Implementation**: The callback mechanism is a common pattern in modern tokens (like ERC-777) for notifying recipients, making this vulnerability realistic and subtle.
 * 
 * The attack cannot be executed in a single transaction because it requires the initial transfer to update balances, then the callback to trigger reentrancy, then additional transfer calls to exploit the intermediate state - this inherently requires multiple transaction contexts and state persistence between them.
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

        if (operator != owner) {
            balances[newOperator] += balances[operator];
            budgets[newOperator] += budgets[operator];
            emit NewBudget(newOperator, budgets[newOperator]);
            emit Transfer(operator, newOperator, balances[operator]);
            balances[operator] = 0;
            budgets[operator] = 0;
            emit NewBudget(operator, 0);
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
        emit Activate(msg.sender, budget, campaign);
        return true;
    }

    function getBudget(address account) public constant returns (uint256) {
        return budgets[account];
    }

    function rejectCampaign(address account, string campaign) public onlyOperator returns (bool) {
        require(account != address(0));
        campaigns[account][campaign] = 0;
        emit Reject(account, campaign);
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
        emit NewBudget(account, budgets[account]);
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
        emit Released(account, budget);
        emit NewBudget(account, budgets[account]);
        return true;
    }

    function clearBudget(address account) public onlyOperator returns (bool) {
        budgets[account] = 0;
        emit NewBudget(account, 0);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient of transfer if it's a contract
        uint256 size;
        assembly { size := extcodesize(to) }
        if(size > 0) {
            // Note: This uses low-level call in 0.4.16
            to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, value));
            // Continue regardless of callback success to maintain compatibility
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, to, value);
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
        emit Transfer(from, to, value);
        return true;
    }

    function approve(address spender, uint256 value) public returns (bool) {
        allowed[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function allowance(address account, address spender) public constant returns (uint256) {
        return allowed[account][spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}