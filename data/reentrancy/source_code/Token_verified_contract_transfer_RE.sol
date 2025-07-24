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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call**: Introduced `_to.call()` to notify recipient contracts about token receipt
 * 2. **Callback Mechanism**: Added `onTokenReceived(address,uint256)` callback that allows recipient contracts to execute custom logic
 * 3. **State Persistence**: The vulnerable external call occurs after balance updates, allowing reentrancy to exploit the updated state
 * 4. **Code Length Check**: Added `_to.code.length > 0` check to only call contracts, making it appear more legitimate
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Setup Phase (Transaction 1):**
 * - Attacker deploys a malicious contract that implements `onTokenReceived`
 * - The malicious contract is designed to re-enter the `transfer` function when called
 * - Attacker ensures they have sufficient tokens to initiate the attack
 * 
 * **Exploitation Phase (Transaction 2):**
 * - Attacker calls `transfer` to send tokens to their malicious contract
 * - When the external call `_to.call()` is made, it triggers the malicious contract's `onTokenReceived` function
 * - The malicious contract immediately calls `transfer` again before the original call completes
 * - Since balances were already updated in the first call, the attacker can drain tokens by repeatedly re-entering
 * 
 * **Example Attack Scenario:**
 * ```solidity
 * // Attacker's malicious contract
 * contract MaliciousReceiver {
 *     RocketCoin target;
 *     bool attacking = false;
 *     
 *     function onTokenReceived(address from, uint256 amount) external {
 *         if (!attacking && target.balanceOf(address(this)) > 0) {
 *             attacking = true;
 *             // Reenter to drain more tokens
 *             target.transfer(msg.sender, target.balanceOf(address(this)));
 *             attacking = false;
 *         }
 *     }
 * }
 * ```
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The vulnerability depends on the persistent state changes in the `balances` mapping that occur across transaction boundaries
 * 2. **Contract Deployment**: The attacker must first deploy a malicious contract in a separate transaction
 * 3. **Reentrancy Chain**: The exploitation requires a chain of calls where each reentrant call depends on the state modifications made by previous calls
 * 4. **Token Accumulation**: The attacker needs to accumulate tokens through multiple transfers to maximize the drainage effect
 * 
 * **Stateful Nature:**
 * - Each successful reentrant call modifies the `balances` mapping persistently
 * - The vulnerability compound across multiple function calls, with each call building upon the state changes from previous calls
 * - The attack's effectiveness depends on the accumulated balance state from prior transactions
 * 
 * This creates a realistic, stateful, multi-transaction reentrancy vulnerability that requires careful orchestration across multiple blockchain transactions to exploit effectively.
 */
pragma solidity ^0.4.18;

contract Token {
    function balanceOf(address _account) public constant returns (uint256 balance);

    mapping(address => uint256) balances;
    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function transfer(address _to, uint256 _amount) public returns (bool success) {
        require(balances[msg.sender] >= _amount && _amount > 0);
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
        
        // Vulnerable: External call before state finalization allows reentrancy
        if (isContract(_to)) {
            // Notify recipient contract of token receipt
            bool callSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _amount));
            // Continue execution regardless of callback success
        }
        
        Transfer(msg.sender, _to, _amount);
        return true;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
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
}
