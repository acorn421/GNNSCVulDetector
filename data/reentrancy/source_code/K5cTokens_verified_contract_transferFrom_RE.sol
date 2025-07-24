/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a callback mechanism that calls the recipient contract's onTokenTransfer function BEFORE updating the allowance and executing the transfer. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **Multi-Transaction Exploitation**: An attacker can set up a malicious contract as the recipient (_to) that implements onTokenTransfer. When this function is called, it can re-enter transferFrom while the allowance is still at its original value.
 * 
 * 2. **Stateful Vulnerability**: The vulnerability depends on the persistent state of the allowance mapping. An attacker can:
 *    - Transaction 1: Set up allowance via approve() 
 *    - Transaction 2: Call transferFrom which triggers the callback, allowing re-entrance while allowance hasn't been decreased yet
 *    - The callback can call transferFrom again, effectively bypassing the allowance check
 * 
 * 3. **Realistic Implementation**: The callback mechanism mimics real-world patterns where tokens notify recipients about incoming transfers, making this a subtle but dangerous vulnerability that could appear in production code.
 * 
 * 4. **CEI Violation**: The external call occurs before state updates (allowance decrease), violating the Checks-Effects-Interactions pattern and enabling reentrancy exploitation across multiple transactions.
 */
pragma solidity ^0.4.16;

// ----------------------------------------------------------------------------
// Safe maths
// ----------------------------------------------------------------------------
contract SafeMath {
    function safeAdd(uint256 a, uint256 b) public pure returns (uint256 c) {
        c = a + b;
        require(c >= a);
    }
    function safeSub(uint256 a, uint256 b) public pure returns (uint256 c) {
        require(b <= a);
        c = a - b;
    }
    function safeMul(uint256 a, uint256 b) public pure returns (uint256 c) {
        c = a * b;
        require(a == 0 || c / a == b);
    }
    function safeDiv(uint256 a, uint256 b) public pure returns (uint256 c) {
        require(b > 0);
        c = a / b;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract K5cTokens is SafeMath {
    // Public variables of the token
    string public   name;
    string public   symbol;
    uint8 public    decimals = 18;                                                  // 18 decimals is the strongly suggested default, avoid changing it

    uint256 public  totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply
    ) public {
        totalSupply             = initialSupply * 10 ** uint256(decimals);          // Update total supply with the decimal amount
        balanceOf[msg.sender]   = totalSupply;                                      // Give the creator all initial tokens
        name                    = "K5C Tokens";                                     // Set the name for display purposes
        symbol                  = "K5C";                                            // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances   = safeAdd(balanceOf[_from], balanceOf[_to]);
        // Subtract from the sender
        balanceOf[_from]        = safeSub(balanceOf[_from], _value);
        // Add the same to the recipient
        balanceOf[_to]          = safeAdd(balanceOf[_to], _value);

        emit Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` on behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);                                // Check allowance
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient before state changes - introduces callback mechanism
        if (isContract(_to)) {
            // Note: abi.encodeWithSignature is not available in 0.4.16, use bytes4 + .call
            // Assuming the target contract is trusted to handle fallback correctly per the inject
            bytes4 sig = bytes4(keccak256("onTokenTransfer(address,address,uint256)"));
            // solium-disable-next-line security/no-low-level-calls
            _to.call(sig, _from, _to, _value);
            // Continue even if callback fails
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        allowance[_from][msg.sender] = safeSub(allowance[_from][msg.sender], _value);   // Decrease allowance
        _transfer(_from, _to, _value);                                                  // Call transfer function
        return true;
    }

    // Helper to check if address is contract (for old Solidity)
    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);                                               // Check if the sender has enough

        balanceOf[msg.sender]           = safeSub(balanceOf[msg.sender], _value);               // Subtract from the sender
        totalSupply                     = safeSub(totalSupply, _value);                         // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                                                    // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);                                        // Check allowance

        balanceOf[_from]                = safeSub(balanceOf[_from], _value);                    // Subtract from the targeted balance
        allowance[_from][msg.sender]    = safeSub(allowance[_from][msg.sender], _value);        // Subtract from the sender's allowance
        totalSupply                     = safeSub(totalSupply, _value);                         // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }


    /**
     * The function without name is the default function that is called whenever anyone sends funds to a contract
     * This is called when ETH is transferred
     */
    function () public payable {
        revert();
    }
}