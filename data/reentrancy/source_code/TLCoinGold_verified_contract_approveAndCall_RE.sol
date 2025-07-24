/*
 * ===== SmartInject Injection Details =====
 * Function      : approveAndCall
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a staged approval mechanism that accumulates pending approvals across multiple calls before processing them. The vulnerability requires:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls approveAndCall() with malicious contract address, triggering the external call to receiveApproval() while pendingApprovals accumulates
 * 2. **Transaction 2**: During the receiveApproval() callback, the malicious contract re-enters approveAndCall() multiple times, each time accumulating more pendingApprovals since approvalInProgress[attacker] is true
 * 3. **Transaction 3+**: The accumulated pendingApprovals value becomes much larger than intended, and when finally processed via approve(), grants excessive allowance to the attacker
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the persistent state in `pendingApprovals` and `approvalInProgress` mappings
 * - Multiple calls are needed to accumulate a dangerous amount in pendingApprovals before the final approve() call
 * - The reentrancy window exists between the external call and the state cleanup, allowing recursive accumulation
 * - Single transaction exploitation is prevented by the staged approval logic that requires building up state over multiple calls
 * 
 * **State Dependencies:**
 * - `pendingApprovals[msg.sender]` accumulates across calls
 * - `approvalInProgress[msg.sender]` tracks ongoing approval processes
 * - The vulnerability requires the state from previous transactions to enable exploitation in subsequent ones
 * 
 * The modified code maintains the original function's intended behavior while introducing a realistic vulnerability pattern seen in complex approval mechanisms.
 */
pragma solidity ^0.4.19;

interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; 
}

contract ERC20 {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function ERC20(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens
        name = tokenName;                                       // Set the name for display purposes
        symbol = tokenSymbol;                                   // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
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
     * Send `_value` tokens to `_to` in behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingApprovals;
    mapping(address => bool) public approvalInProgress;
    
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Stage 1: Accumulate pending approvals across multiple calls
        if (!approvalInProgress[msg.sender]) {
            pendingApprovals[msg.sender] += _value;
            approvalInProgress[msg.sender] = true;
            
            // External call before finalizing state - reentrancy window
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            
            // Stage 2: Process accumulated approvals (vulnerable to reentrancy)
            if (pendingApprovals[msg.sender] > 0) {
                approve(_spender, pendingApprovals[msg.sender]);
                // State cleanup happens after external call - vulnerable window
                pendingApprovals[msg.sender] = 0;
                approvalInProgress[msg.sender] = false;
            }
            return true;
        } else {
            // Allow accumulation during ongoing approval process
            pendingApprovals[msg.sender] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

}

/******************************************/
/*       TLCG TOKEN STARTS HERE       */
/******************************************/

contract TLCoinGold is ERC20 {


    /* Initializes contract with initial supply tokens to the creator of the contract */
    function TLCoinGold() ERC20(10000000, "TL Coin Gold", "TLCG") public {}


    function multisend(address[] dests, uint256[] values) public returns (uint256) {
        uint256 i = 0;
        while (i < dests.length) {
           transfer(dests[i], values[i]);
           i += 1;
        }
        return(i);
    }
    
}