/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawToAdmin
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This creates a multi-transaction reentrancy vulnerability where users must first call requestWithdrawal() to set up their withdrawal request, then call withdrawToAdmin() to execute it. The vulnerability occurs because the external call to adminWallet happens before the state variables are updated, allowing for reentrancy attacks across multiple transactions. An attacker can exploit this by: 1) First calling requestWithdrawal() to set up the withdrawal, 2) Then calling withdrawToAdmin() which makes an external call before updating balances, 3) During the external call, the attacker can re-enter and call withdrawToAdmin() again since the state hasn't been updated yet.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-03-30
*/

pragma solidity ^0.4.22;

contract Natterix {

    string public name = "Natterix";
    string public symbol = "NRX";
    uint256 public constant decimals = 18;
    address public adminWallet;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;
    uint public constant supplyNumber = 500000000;
    uint public constant powNumber = 10;
    uint public constant TOKEN_SUPPLY_TOTAL = supplyNumber * powNumber ** decimals;
    uint256 constant valueFounder = TOKEN_SUPPLY_TOTAL;
    address owner = 0x0;

    mapping(address => uint256) public withdrawalRequests;
    mapping(address => bool) public withdrawalInProgress;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    function requestWithdrawal(uint256 _amount) public isRunning validAddress {
        require(balanceOf[msg.sender] >= _amount);
        require(!withdrawalInProgress[msg.sender]);
        withdrawalRequests[msg.sender] = _amount;
    }
    
    function withdrawToAdmin() public isRunning validAddress {
        require(withdrawalRequests[msg.sender] > 0);
        require(!withdrawalInProgress[msg.sender]);
        
        uint256 amount = withdrawalRequests[msg.sender];
        withdrawalInProgress[msg.sender] = true;
        
        // Vulnerable external call before state update
        bool success = adminWallet.call.value(amount)("");
        require(success);
        
        // State updates after external call - vulnerable to reentrancy
        balanceOf[msg.sender] -= amount;
        withdrawalRequests[msg.sender] = 0;
        withdrawalInProgress[msg.sender] = false;
        
        emit Transfer(msg.sender, 0x0, amount);
    }
    // === END FALLBACK INJECTION ===

    modifier isRunning {
        assert(!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor() public {
        owner = msg.sender;
        adminWallet = owner;
        totalSupply = valueFounder;
        balanceOf[owner] = valueFounder;
        emit Transfer(0x0, owner, valueFounder);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {

        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() public isOwner {
        stopped = true;
    }

    function start() public isOwner {
        stopped = false;
    }

    function setName(string _name) public isOwner {
        name = _name;
    }

    function setSymbol(string _symbol) public isOwner {
        symbol = _symbol;
    }

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
