/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract AFTER state updates (balances modification). The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a callback mechanism that calls `onTokenReceived()` on recipient contracts
 * 2. Placed the external call AFTER the state changes (violating Checks-Effects-Interactions pattern)
 * 3. Used a low-level call that doesn't revert on failure, allowing the transfer to complete
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract with `onTokenReceived()` function
 * 2. **Transaction 2**: Attacker obtains initial tokens (either through purchase, airdrop, or other means)
 * 3. **Transaction 3**: Attacker calls `transfer()` to send tokens to their malicious contract
 * 4. **During Transaction 3**: The malicious contract's `onTokenReceived()` is called, which can:
 *    - Re-enter the `transfer()` function before the original call completes
 *    - Since balances were already updated, the malicious contract can transfer tokens again
 *    - This can be done multiple times in nested calls, draining tokens
 * 
 * **Why Multi-Transaction is Required:**
 * - **State Accumulation**: The attacker needs to accumulate tokens across multiple transactions before exploitation
 * - **Contract Deployment**: The malicious contract must be deployed in a separate transaction
 * - **Setup Phase**: The attacker needs to position tokens and contracts across multiple transactions
 * - **Exploitation Sequence**: Each reentrancy attempt modifies the balance state, requiring multiple transfer calls to achieve significant impact
 * 
 * **Stateful Nature:**
 * - The vulnerability depends on the persistent `balances` mapping state
 * - Each transaction modifies this state, affecting subsequent transactions
 * - The exploit leverages the fact that state changes persist between the external call and function completion
 * 
 * This creates a realistic vulnerability where the external call enables reentrancy but requires careful multi-transaction setup and execution to be effective.
 */
pragma solidity ^0.4.18;

contract Token {
    function balanceOf(address _account) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
}

contract RocketCoin {
    string public constant symbol = "XRC";
    string public constant name = "Rocket Coin";
    uint public constant decimals = 18;
    uint public constant totalSupply = 10000000 * 10 ** decimals;
    address owner;
    bool airDropStatus = true;
    uint airDropAmount = 300 * 10 ** decimals;
    uint airDropGasPrice = 20 * 10 ** 9;
    mapping (address => bool) participants;
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public {
        owner = msg.sender;
        balances[owner] = totalSupply;
        emit Transfer(address(0), owner, totalSupply);
    }

    function() public payable {
        require(airDropStatus && balances[owner] >= airDropAmount && !participants[msg.sender] && tx.gasprice >= airDropGasPrice);
        balances[owner] -= airDropAmount;
        balances[msg.sender] += airDropAmount;
        emit Transfer(owner, msg.sender, airDropAmount);
        participants[msg.sender] = true;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function transfer(address _to, uint256 _amount) public returns (bool success) {
        require(balances[msg.sender] >= _amount && _amount > 0);
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
        emit Transfer(msg.sender, _to, _amount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient if it's a contract
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _amount));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    function multiTransfer(address[] _addresses, uint[] _amounts) public returns (bool success) {
        require(_addresses.length <= 100 && _addresses.length == _amounts.length);
        uint totalAmount;
        for (uint a = 0; a < _amounts.length; a++) {
            totalAmount += _amounts[a];
        }
        require(totalAmount > 0 && balances[msg.sender] >= totalAmount);
        balances[msg.sender] -= totalAmount;
        for (uint b = 0; b < _addresses.length; b++) {
            if (_amounts[b] > 0) {
                balances[_addresses[b]] += _amounts[b];
                emit Transfer(msg.sender, _addresses[b], _amounts[b]);
            }
        }
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) {
        require(balances[_from] >= _amount && allowed[_from][msg.sender] >= _amount && _amount > 0);
        balances[_from] -= _amount;
        allowed[_from][msg.sender] -= _amount;
        balances[_to] += _amount;
        emit Transfer(_from, _to, _amount);
        return true;
    }

    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        emit Approval(msg.sender, _spender, _amount);
        return true;
    }

    function setupAirDrop(bool _status, uint _amount, uint _Gwei) public returns (bool success) {
        require(msg.sender == owner);
        airDropStatus = _status;
        airDropAmount = _amount * 10 ** decimals;
        airDropGasPrice = _Gwei * 10 ** 9;
        return true;
    }

    function withdrawFunds(address _token) public returns (bool success) {
        require(msg.sender == owner);
        if (_token == address(0)) {
            owner.transfer(this.balance);
        }
        else {
            Token ERC20 = Token(_token);
            ERC20.transfer(owner, ERC20.balanceOf(this));
        }
        return true;
    }
}