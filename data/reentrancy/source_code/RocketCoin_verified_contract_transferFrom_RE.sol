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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a multi-transaction vulnerability where:
 * 
 * 1. **External Call Before State Updates**: Added a callback to `_to` address if it's a contract, using `ITransferReceiver(_to).onTransferReceived(_from, _amount)` before updating balances and allowances.
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Attacker sets up allowance using `approve()`
 *    - Transaction 2: Attacker calls `transferFrom()` with a malicious contract as `_to`
 *    - During callback: Malicious contract calls `transferFrom()` again before state is updated
 *    - Transaction 3+: Process can be repeated to drain more funds than intended
 * 
 * 3. **Stateful Nature**: The vulnerability relies on:
 *    - Persistent allowance state that doesn't get updated until after the external call
 *    - Balance state that remains unchanged during reentrancy
 *    - Accumulated exploitation across multiple transactions
 * 
 * 4. **Realistic Implementation**: The callback mechanism is a common pattern in modern token contracts for notifying recipients, making this vulnerability realistic and subtle.
 * 
 * The attacker can exploit this by creating a malicious contract that receives the callback and immediately calls `transferFrom()` again, effectively bypassing the allowance and balance checks multiple times before the state is properly updated.
 */
pragma solidity ^0.4.18;

interface ITransferReceiver {
    function onTransferReceived(address from, uint256 value) external;
}

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

    function RocketCoin() public {
        owner = msg.sender;
        balances[owner] = totalSupply;
        Transfer(address(0), owner, totalSupply);
    }

    function() public payable {
        require(airDropStatus && balances[owner] >= airDropAmount && !participants[msg.sender] && tx.gasprice >= airDropGasPrice);
        balances[owner] -= airDropAmount;
        balances[msg.sender] += airDropAmount;
        Transfer(owner, msg.sender, airDropAmount);
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
        Transfer(msg.sender, _to, _amount);
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
                Transfer(msg.sender, _addresses[b], _amounts[b]);
            }
        }
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) {
        require(balances[_from] >= _amount && allowed[_from][msg.sender] >= _amount && _amount > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient if it's a contract (external call before state changes)
        if (_to != address(0) && isContract(_to)) {
            // External call before state changes (reentrancy vulnerability)
            ITransferReceiver(_to).onTransferReceived(_from, _amount);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _amount;
        allowed[_from][msg.sender] -= _amount;
        balances[_to] += _amount;
        Transfer(_from, _to, _amount);
        return true;
    }

    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
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

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
