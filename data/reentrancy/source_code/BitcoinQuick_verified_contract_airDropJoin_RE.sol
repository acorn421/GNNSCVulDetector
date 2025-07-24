/*
 * ===== SmartInject Injection Details =====
 * Function      : airDropJoin
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by reordering the operations to place the airDropMembers and airDropHeight state updates AFTER the external call to msg.sender.transfer(). This creates a critical window where:
 * 
 * 1. **Transaction 1**: Attacker calls airDropJoin() with a malicious contract that has a fallback/receive function. The function processes the airdrop, transfers tokens, but before updating airDropMembers[msg.sender] = true, it calls the attacker's contract via transfer().
 * 
 * 2. **Transaction 2**: The attacker's contract fallback function immediately calls airDropJoin() again. Since airDropMembers[msg.sender] is still false (not yet updated), the require check passes again, allowing a second airdrop claim.
 * 
 * 3. **State Accumulation**: Each reentrant call accumulates more tokens in the attacker's account while the membership status remains unchanged until the very end of each call stack.
 * 
 * The vulnerability is multi-transaction because:
 * - The first transaction sets up the state (tokens transferred but membership not updated)
 * - The reentrant transaction exploits this inconsistent state
 * - Multiple nested calls can drain the airdrop supply before any membership updates occur
 * - Each level of reentrancy represents a separate logical transaction in the call stack
 * 
 * This is realistic because it mimics real-world patterns where developers might move external calls earlier in functions for gas optimization or user experience reasons, inadvertently creating reentrancy windows in state-dependent operations.
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

    event Transfer(address indexed _from, address indexed _to, uint _value);

    event Approval(address indexed _owner, address indexed _spender, uint _value);

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
        // Transfer funds
        marketSupply -= unitsFinal;
        accounts[owner] -= unitsFinal;
        accounts[msg.sender] += unitsFinal;
        Transfer(owner, msg.sender, unitsFinal);
        // Calculate remaining ether amount
        uint remainEther = msg.value - (unitsFinal * marketPrice);
        // Return extra ETH to sender
        if (remainEther > 0) {
            msg.sender.transfer(remainEther);
        }
        return true;
    }

    function airDropJoin(bytes32 _secret) public payable returns (bool _status) {
        // Checkout airdrop conditions and eligibility
        require(!airDropMembers[msg.sender] && airDrop(airDropVerify).verify(msg.sender, _secret) && airDropHeight > 0 && airDropAmount > 0 && accounts[owner] >= airDropAmount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Transfer amount immediately but delay membership update
        accounts[owner] -= airDropAmount;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        accounts[msg.sender] += airDropAmount;
        Transfer(owner, msg.sender, airDropAmount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Return extra amount to sender before updating membership status
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (msg.value > 0) {
            msg.sender.transfer(msg.value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update membership status after external call - VULNERABILITY POINT
        airDropMembers[msg.sender] = true;
        airDropHeight--;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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