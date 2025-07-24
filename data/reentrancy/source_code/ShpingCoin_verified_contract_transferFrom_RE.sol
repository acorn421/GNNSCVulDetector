/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires:
 * 
 * 1. **Transaction 1**: Attacker deploys malicious contract and gets approval via approve()
 * 2. **Transaction 2**: Attacker calls transferFrom() which triggers the external call before state updates
 * 3. **Reentrant calls**: The malicious contract can re-enter transferFrom() multiple times before the original state updates complete
 * 
 * **Exploitation Mechanism:**
 * - The external call `ITokenReceiver(to).onTokenReceived(from, value)` happens before balances and allowances are updated
 * - A malicious recipient contract can implement `onTokenReceived()` to call back into `transferFrom()` 
 * - During reentrancy, the original allowance and balance checks still pass because state hasn't been updated yet
 * - Each reentrant call can transfer the same tokens again, effectively multiplying the attacker's balance
 * 
 * **Multi-Transaction Requirements:**
 * - Requires initial approval transaction to set up allowances
 * - Requires subsequent transferFrom() call to trigger the vulnerability
 * - The vulnerability accumulates effect across multiple reentrant calls within the same transaction
 * - However, the setup requires multiple transactions and the exploitation depends on state that persists between transactions (allowances, balances)
 * 
 * **Realistic Nature:**
 * - Token recipient notification is a common pattern in modern ERC20 implementations
 * - The try/catch pattern makes it appear like defensive programming
 * - The code maintains all original functionality while introducing the flaw
 * 
 * This creates a classic reentrancy vulnerability where external calls happen before state updates, violating the Checks-Effects-Interactions pattern in a stateful, multi-transaction context.
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

    function ShpingCoin() public {
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
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Solidity 0.4.x does not support try...catch or .code, so we simulate a call style
        if (isContract(to)) {
            ITokenReceiver(to).onTokenReceived(from, value);
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    // Utility to detect if address is contract in 0.4.x fashion
    function isContract(address _addr) internal constant returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}

// Minimal ITokenReceiver interface for reentrancy injection and compilation
interface ITokenReceiver {
    function onTokenReceived(address from, uint256 value) external;
}