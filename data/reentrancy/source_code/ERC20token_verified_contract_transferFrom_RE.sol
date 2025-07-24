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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a recipient contract's onTokenReceived function BEFORE state updates. This creates a classic reentrancy pattern where:
 * 
 * 1. **External Call Before State Changes**: The function calls _to.onTokenReceived() before updating balances and allowances
 * 2. **Stateful Exploitation**: The recipient contract can re-enter transferFrom during the callback while the original transaction's state changes haven't been applied yet
 * 3. **Multi-Transaction Requirement**: The vulnerability requires multiple transactions to be effectively exploited:
 *    - Transaction 1: Attacker calls transferFrom with malicious recipient contract
 *    - During the onTokenReceived callback, the malicious contract can call transferFrom again or manipulate allowances
 *    - Transaction 2+: Attacker exploits the inconsistent state created by partial execution
 *    - The vulnerability persists across transactions due to state inconsistencies
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * - **Setup Phase**: Attacker deploys malicious contract with onTokenReceived callback
 * - **Transaction 1**: Call transferFrom with malicious contract as _to address
 * - **Reentrancy**: During onTokenReceived callback, call transferFrom again or approve more tokens
 * - **Transaction 2**: Exploit accumulated state changes or allowance manipulations
 * - **Persistence**: State inconsistencies from partial executions accumulate between transactions
 * 
 * This vulnerability is realistic because token recipient notifications are common in modern standards (like ERC777), but the improper ordering of external calls before state updates creates a classic reentrancy attack vector that requires multiple transactions to fully exploit.
 */
pragma solidity ^0.4.16;

contract ERC20token{
    uint256 public totalSupply;
    string public name;
    uint8 public decimals;
    string public symbol;
    address public admin;
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    mapping (address => bool) public frozenAccount; //无限期冻结的账户
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    
    // Changed to constructor per modern Solidity requirements
    function ERC20token(uint256 _initialAmount, string _tokenName, uint8 _decimalUnits, string _tokenSymbol) public {
        totalSupply = _initialAmount * 10 ** uint256(_decimalUnits);
        balances[msg.sender] = totalSupply;
        admin = msg.sender;
        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(!frozenAccount[msg.sender]);
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(!frozenAccount[msg.sender]);
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if recipient is a contract and notify before state changes
        if (isContract(_to)) {
            // External call before state updates - vulnerable to reentrancy
            bool notifyResult = TokenReceiver(_to).onTokenReceived(_from, msg.sender, _value);
            require(notifyResult);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    // Helper function to determine if address is a contract in Solidity 0.4.x
    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }
    
     function freeze(address _target,bool _freeze) public returns (bool) {
        require(msg.sender == admin);
        // require(_target != address(0));
        // require(_target != admin);
        frozenAccount[_target] = _freeze;
        return true;
    }
    
    // function cgadmin(address _newadmin) public returns (bool){
    //      require(msg.sender == admin);
    // }
    
    function approve(address _spender, uint256 _value) public returns (bool success)
    {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}

// TokenReceiver interface must be present for the code to compile
interface TokenReceiver {
    function onTokenReceived(address _from, address _operator, uint256 _value) external returns (bool);
}
