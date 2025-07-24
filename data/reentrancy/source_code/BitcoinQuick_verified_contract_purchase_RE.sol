/*
 * ===== SmartInject Injection Details =====
 * Function      : purchase
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Persistence**: Introduced `pendingRefunds` mapping to track accumulated refund amounts across transactions
 * 2. **Moved External Call Before State Update**: The `msg.sender.transfer(refundAmount)` now occurs before `pendingRefunds[msg.sender] = 0`
 * 3. **Created Multi-Transaction Dependency**: The vulnerability requires multiple purchase transactions to build up sufficient `pendingRefunds` balance before exploitation
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1-N**: Attacker makes multiple small purchases, each building up pendingRefunds balance
 * - **Transaction N+1**: Attacker triggers the vulnerability through reentrancy, calling purchase() again during the transfer callback
 * - **Exploitation**: During reentrancy, pendingRefunds[attacker] still contains the accumulated amount (not yet zeroed), allowing multiple withdrawals of the same refund
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The attacker needs to build up a meaningful pendingRefunds balance across multiple transactions
 * 2. **Threshold Dependency**: Single transaction refunds are typically small; multiple transactions create larger exploitable amounts
 * 3. **Realistic Attack Vector**: Mimics real-world scenarios where refunds accumulate over time before being processed
 * 
 * This creates a realistic vulnerability where an attacker must perform multiple legitimate purchases to accumulate refunds, then exploit the reentrancy to drain the accumulated amount multiple times.
 */
pragma solidity ^0.4.16;

contract airDrop {
    function verify(address _address, bytes32 _secret) public constant returns (bool _status);
}

contract BitcoinQuick {
    string public constant symbol = "BTCQ";

    string public constant name = "Bitcoin Quick";

    uint public constant decimals = 8;

    uint _totalSupply = 21000000 * 10 ** decimals;

    uint public marketSupply;

    uint public marketPrice;

    address owner;

    address airDropVerify;

    uint public airDropAmount;

    uint32 public airDropHeight;

    mapping (address => bool) public airDropMembers;

    mapping (address => uint) accounts;

    mapping (address => mapping (address => uint)) allowed;

    // Added declaration for pendingRefunds mapping
    mapping (address => uint) pendingRefunds;

    event Transfer(address indexed _from, address indexed _to, uint _value);

    event Approval(address indexed _owner, address indexed _spender, uint _value);

    // Changed constructor syntax for older Solidity ver <0.5.0
    function BitcoinQuick() public {
        owner = msg.sender;
        accounts[owner] = _totalSupply;
        Transfer(address(0), owner, _totalSupply);
    }

    function totalSupply() public constant returns (uint __totalSupply) {
        return _totalSupply;
    }

    function balanceOf(address _account) public constant returns (uint balance) {
        return accounts[_account];
    }

    function allowance(address _account, address _spender) public constant returns (uint remaining) {
        return allowed[_account][_spender];
    }

    function transfer(address _to, uint _amount) public returns (bool success) {
        require(_amount > 0 && accounts[msg.sender] >= _amount);
        accounts[msg.sender] -= _amount;
        accounts[_to] += _amount;
        Transfer(msg.sender, _to, _amount);
        return true;
    }

    function transferFrom(address _from, address _to, uint _amount) public returns (bool success) {
        require(_amount > 0 && accounts[_from] >= _amount && allowed[_from][msg.sender] >= _amount);
        accounts[_from] -= _amount;
        allowed[_from][msg.sender] -= _amount;
        accounts[_to] += _amount;
        Transfer(_from, _to, _amount);
        return true;
    }

    function approve(address _spender, uint _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }

    function purchase() public payable returns (bool _status) {
        require(msg.value > 0 && marketSupply > 0 && marketPrice > 0 && accounts[owner] > 0);
        // Calculate available and required units
        uint unitsAvailable = accounts[owner] < marketSupply ? accounts[owner] : marketSupply;
        uint unitsRequired = msg.value / marketPrice;
        uint unitsFinal = unitsAvailable < unitsRequired ? unitsAvailable : unitsRequired;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add to pending refunds for batch processing
        pendingRefunds[msg.sender] += msg.value - (unitsFinal * marketPrice);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        // Transfer funds
        marketSupply -= unitsFinal;
        accounts[owner] -= unitsFinal;
        accounts[msg.sender] += unitsFinal;
        Transfer(owner, msg.sender, unitsFinal);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Process pending refunds if available
        if (pendingRefunds[msg.sender] > 0) {
            uint refundAmount = pendingRefunds[msg.sender];
            // VULNERABILITY: External call before state update
            msg.sender.transfer(refundAmount);
            // State update after external call - vulnerable to reentrancy
            pendingRefunds[msg.sender] = 0;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
        return true;
    }

    function airDropJoin(bytes32 _secret) public payable returns (bool _status) {
        // Checkout airdrop conditions and eligibility
        require(!airDropMembers[msg.sender] && airDrop(airDropVerify).verify(msg.sender, _secret) && airDropHeight > 0 && airDropAmount > 0 && accounts[owner] >= airDropAmount);
        // Transfer amount
        accounts[owner] -= airDropAmount;
        accounts[msg.sender] += airDropAmount;
        airDropMembers[msg.sender] = true;
        Transfer(owner, msg.sender, airDropAmount);
        airDropHeight--;
        // Return extra amount to sender
        if (msg.value > 0) {
            msg.sender.transfer(msg.value);
        }
        return true;
    }

    function airDropSetup(address _contract, uint32 _height, uint _units) public returns (bool _status) {
        require(msg.sender == owner);
        airDropVerify = _contract;
        airDropHeight = _height;
        airDropAmount = _units * 10 ** decimals;
        return true;
    }

    function crowdsaleSetup(uint _supply, uint _perEther) public returns (bool _status) {
        require(msg.sender == owner && accounts[owner] >= _supply * 10 ** decimals);
        marketSupply = _supply * 10 ** decimals;
        marketPrice = 1 ether / (_perEther * 10 ** decimals);
        return true;
    }

    function withdrawFunds(uint _amount) public returns (bool _status) {
        require(msg.sender == owner && _amount > 0 && this.balance >= _amount);
        owner.transfer(_amount);
        return true;
    }
}
