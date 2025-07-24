/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the _from address before state updates. This creates a classic reentrancy scenario where:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_from.call()` with burn notification before state modifications
 * 2. The call invokes `onBurnFrom(address,uint256)` on the _from address if it's a contract
 * 3. State updates (balanceOf, allowance, totalSupply) happen AFTER the external call
 * 4. Added require statement to ensure call success, making the vulnerability more realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract at address A with large balance and allowance
 * 2. **Transaction 2**: Attacker calls burnFrom(A, amount) from external account
 * 3. **During callback**: Malicious contract A's onBurnFrom function calls burnFrom again with same parameters
 * 4. **State persistence**: Since state hasn't been updated yet, the second call sees the original balances
 * 5. **Double burn**: Both calls succeed, burning twice the intended amount while only reducing allowance once
 * 6. **Accumulated effect**: Each subsequent transaction can exploit the same pattern with remaining balances
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires setting up initial state (balances/allowances) in separate transactions
 * - Each exploitation requires the external call to trigger during state-checking phase
 * - The accumulated state changes persist between transactions, enabling repeated exploitation
 * - The reentrancy depends on the contract state being inconsistent across multiple call frames
 * - Single transaction exploitation is limited by gas and call depth, but multi-transaction allows unlimited exploitation
 * 
 * **Realistic Nature:**
 * - Burn notification is a common pattern in DeFi protocols for hooks and integrations
 * - The vulnerability follows real-world reentrancy patterns seen in production contracts
 * - The code maintains original functionality while introducing the security flaw
 * - The pattern violates Checks-Effects-Interactions principle in a subtle way
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;
    function owned() public {
        owner = msg.sender;
    }
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/// ERC20 standard，Define the minimum unit of money to 18 decimal places,
/// transfer out, destroy coins, others use your account spending pocket money.
contract TokenERC20 {
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    /**
     * Internal transfer, only can be called by this contract.
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account.
     *
     * @param _to The address of the recipient.
     * @param _value the amount to send.
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address.
     *
     * Send `_value` tokens to `_to` in behalf of `_from`.
     *
     * @param _from The address of the sender.
     * @param _to The address of the recipient.
     * @param _value the amount to send.
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address.
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf.
     *
     * @param _spender The address authorized to spend.
     * @param _value the max amount they can spend.
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        require((_value == 0) || (allowance[msg.sender][_spender] == 0));
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify.
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it.
     *
     * @param _spender The address authorized to spend.
     * @param _value the max amount they can spend.
     * @param _extraData some extra information to send to the approved contract.
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

     /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly.
     *
     * @param _value the amount of money to burn.
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account.
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender.
     * @param _value the amount of money to burn.
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // INJECTED: External call to notify burn recipient before state changes
        if(_from.call.gas(50000).value(0)(bytes4(keccak256("onBurnFrom(address,uint256)")), msg.sender, _value)) {
            // successful external call
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}

/****************************/
/*       ------------        */
/*       HGH TOKEN        */
/*       ------------        */
/****************************/

/// HGH Protocol Token.
contract HGHToken is owned, TokenERC20 {

    string public constant name = "Human Growth Hormone";
    string public constant symbol = "HGH";
    uint8 public constant decimals = 0;

    /* Initializes contract with initial supply tokens to the creator of the contract. */
    function HGHToken() public {
        totalSupply = 1000000;
        balanceOf[msg.sender] = totalSupply;
    }

    function mint(uint amount) onlyOwner public {
        require(amount != 0x0);
        require(amount < 1e60);
        require(totalSupply + amount > totalSupply);
   
        totalSupply += amount;
        balanceOf[msg.sender] += amount;
    }
}
