/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before updating balances. This creates a classic Checks-Effects-Interactions pattern violation where:
 * 
 * 1. **Multi-Transaction Setup**: Transaction 1 - Attacker deploys a malicious contract with onTokenReceived callback. Transaction 2 - Attacker calls transfer() to send tokens to their malicious contract.
 * 
 * 2. **Reentrancy Exploitation**: When transfer() is called, it makes an external call to the recipient's onTokenReceived function BEFORE updating balances. The malicious contract can re-enter the transfer function, passing the balance check (since sender's balance hasn't been decremented yet) and repeat the process.
 * 
 * 3. **State Persistence**: The vulnerability persists across multiple transactions because:
 *    - The attacker's malicious contract remains deployed between transactions
 *    - The victim's balance remains unchanged until after the external call
 *    - Each reentrant call can drain more funds before the original balance update occurs
 * 
 * 4. **Multi-Transaction Requirement**: 
 *    - Cannot be exploited in a single transaction without prior setup
 *    - Requires the attacker to first deploy their malicious contract
 *    - Requires the victim to actually call transfer() to the malicious contract address
 *    - The exploitation spans multiple call frames within the transaction, creating a stateful attack sequence
 * 
 * This vulnerability is realistic as it mimics modern token standards (ERC721, ERC1155) that include recipient callbacks, but implements them insecurely by violating the Checks-Effects-Interactions pattern.
 */
pragma solidity ^0.4.18;

contract ERC20Token {
    uint256 public totalSupply;
    mapping (address => uint256) public balances; // Added mapping to fix undefined balances
    function balanceOf(address _owner) public view returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Check if recipient is a contract and notify them of the transfer
        // Fix: Use extcodesize instead of _to.code.length (not available in 0.4.18)
        uint256 length;
        assembly { length := extcodesize(_to) }
        if (length > 0) {
            // External call BEFORE state update - vulnerable to reentrancy
            // Fix for .call return value in Solidity 0.4.x
            require(_to.call(
                bytes4(keccak256("onTokenReceived(address,uint256)")),
                msg.sender, _value
            ));
        }

        // State updates happen AFTER external call - vulnerable pattern
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract BeBitcoin is ERC20Token {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    // mapping (address => uint256) public balances; // inherited
    mapping (address => mapping (address => uint256)) public allowed;

    string public name;
    uint8 public decimals;             
    string public symbol;              

    constructor (
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;              
        totalSupply = _initialAmount;                       
        name = _tokenName;                                 
        decimals = _decimalUnits;  
        symbol = _tokenSymbol;  
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }   
}
