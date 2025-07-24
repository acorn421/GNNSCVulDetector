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
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify recipient contracts after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `ITokenReceiver(_to).onTokenReceived(msg.sender, _value)` after state updates
 * 2. The call is made to recipient contracts (checked via `_to.code.length > 0`)
 * 3. State updates (balance modifications) occur BEFORE the external call, creating the reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements `ITokenReceiver`
 * 2. **Transaction 2**: Attacker accumulates tokens in their account through normal transfers
 * 3. **Transaction 3**: Attacker calls `transfer()` to send tokens to their malicious contract
 * 4. **Within Transaction 3**: The malicious contract's `onTokenReceived()` callback is triggered, allowing it to:
 *    - Call `transfer()` again before the original transaction completes
 *    - Exploit the inconsistent state where balances are updated but the transaction isn't complete
 *    - Potentially drain tokens by repeatedly calling transfer with the same balance
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker needs to first obtain tokens (Transaction 1-2)
 * - The attacker needs to deploy the malicious receiver contract (separate transaction)
 * - The exploitation occurs when transferring to the malicious contract (Transaction 3)
 * - The vulnerability is stateful because it depends on the accumulated token balance from previous transactions
 * - Without sufficient balance from prior transactions, the reentrancy attack cannot drain significant funds
 * 
 * **State Persistence Factor:**
 * - The vulnerability depends on the persistent `balanceOf` state accumulated across multiple transactions
 * - Each successful exploitation can modify the persistent state, enabling further attacks
 * - The attack's impact scales with the amount of tokens accumulated in previous transactions
 */
pragma solidity ^0.4.11;

contract EthereumSoft {

    string public name = "Ethereum Soft";      //  Soft name
    string public symbol = "ESFT";           //  Soft symbol
    uint256 public decimals = 1;            //  Soft digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 5000000 * (10**decimals);
    address public owner;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }
    function EthereumSoft() public {
        owner = msg.sender;
        balanceOf[owner] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient if it's a contract
        if (isContract(_to)) {
            ITokenReceiver(_to).onTokenReceived(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success)
    {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function setName(string _name) public isOwner 
    {
        name = _name;
    }
    function burnSupply(uint256 _amount) public isOwner
    {
        balanceOf[owner] -= _amount;
        SupplyBurn(_amount);
    }
    function burnTotalSupply(uint256 _amount) public isOwner
    {
        totalSupply-= _amount;
    }
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event SupplyBurn(uint256 _amount);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}

interface ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value) external;
}
