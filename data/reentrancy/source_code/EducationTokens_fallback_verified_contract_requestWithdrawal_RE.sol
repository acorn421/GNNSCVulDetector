/*
 * ===== SmartInject Injection Details =====
 * Function      : requestWithdrawal
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This creates a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires: 1) First transaction to call requestWithdrawal() setting up the withdrawal state, 2) Second transaction to call processWithdrawal() which makes an external call before updating state. An attacker can exploit this by creating a malicious contract that recursively calls processWithdrawal() during the external call, allowing multiple withdrawals of the same amount before the state is properly updated. The vulnerability is stateful because it depends on the withdrawalPending and withdrawalProcessing mappings persisting between transactions.
 */
pragma solidity ^0.4.25;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b > 0);
        uint256 c = a / b;
        assert(a == b * c);
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a - b;
        assert(b <= a);
        assert(a == c + b);
        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        assert(a == c - b);
        return c;
    }
}

contract owned {
    address public owner;
    
    constructor() public{
        owner = msg.sender;
    }
    
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    
    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}

contract EducationTokens is owned{
    using SafeMath for uint256;

    bool private transferFlag;
    string public name;
    uint256 public decimals;
    string public symbol;
    string public version;
    uint256 public totalSupply;
    uint256 public deployTime;

    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowed;
    mapping(address => uint256) private userLockedTokens;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Lock(address userAddress, uint256 amount);
    event Unlock(address userAddress,uint256 amount);
    event SetFlag(bool flag);

    //constructor(string tokenName, string tokenSymbol) public {
    constructor() public {
        transferFlag = true;
        //name = tokenName;
        name = "sniperyao";
        decimals = 4;
        //symbol = tokenSymbol;
        symbol = "sy";
        version = "V1.0";
        totalSupply = 2100000000 * 10 ** decimals;
        owner = msg.sender;
        deployTime = block.timestamp;
        
        balances[msg.sender] = totalSupply;
    }
    
    modifier canTransfer() {
        require(transferFlag);
        _;
    }
    
    function name()constant public returns (string token_name){
        return name;
    }
    
    function symbol() constant public returns (string _symbol){
        return symbol;
    }
    
    function decimals() constant public returns (uint256 _decimals){
        return decimals;
    }
    
    function totalSupply() constant public returns (uint256 _totalSupply){
        return totalSupply;
    }
    
    function setTransferFlag(bool transfer_flag) public onlyOwner{
        transferFlag = transfer_flag;
        emit SetFlag(transferFlag);
    }
    
    function tokenLock(address _userAddress, uint256 _amount) public onlyOwner {
        require(balanceOf(_userAddress) >= _amount);
        userLockedTokens[_userAddress] = userLockedTokens[_userAddress].add(_amount);
        emit Lock(_userAddress, _amount);
    }

    function tokenUnlock(address _userAddress, uint256 _amount) public onlyOwner {
        require(userLockedTokens[_userAddress] >= _amount);
        userLockedTokens[_userAddress] = userLockedTokens[_userAddress].sub(_amount);
        emit Unlock(_userAddress, _amount);
    }

    function balanceOf(address _owner) view public returns (uint256 balance) {
        return balances[_owner] - userLockedTokens[_owner];
    }
    
    function transfer(address _to, uint256 _value) public canTransfer returns (bool success) {
        require(balanceOf(msg.sender) >= _value);
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public canTransfer returns (bool success) {
        require(balanceOf(_from) >= _value && allowed[_from][msg.sender] >= _value);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant public returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
mapping(address => uint256) public withdrawalRequests;
mapping(address => uint256) public withdrawalPending;
mapping(address => bool) public withdrawalProcessing;

event WithdrawalRequested(address indexed user, uint256 amount);
event WithdrawalProcessed(address indexed user, uint256 amount);

function requestWithdrawal(uint256 _amount) public {
    require(balanceOf(msg.sender) >= _amount, "Insufficient balance");
    require(!withdrawalProcessing[msg.sender], "Withdrawal already in progress");
    
    withdrawalRequests[msg.sender] = _amount;
    withdrawalPending[msg.sender] = _amount;
    withdrawalProcessing[msg.sender] = true;
    
    emit WithdrawalRequested(msg.sender, _amount);
}

function processWithdrawal() public {
    require(withdrawalProcessing[msg.sender], "No withdrawal request found");
    require(withdrawalPending[msg.sender] > 0, "No pending withdrawal");
    
    uint256 amount = withdrawalPending[msg.sender];
    
    // Vulnerable: External call before state update
    if (msg.sender.call.value(amount)("")) {
        // State updates happen after external call - reentrancy possible
        withdrawalPending[msg.sender] = 0;
        withdrawalProcessing[msg.sender] = false;
        balances[msg.sender] = balances[msg.sender].sub(amount);
        
        emit WithdrawalProcessed(msg.sender, amount);
    }
}
    // === END FALLBACK INJECTION ===

}