/*
 * ===== SmartInject Injection Details =====
 * Function      : receiveApproval
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
 * 2. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a multi-stage approval processing system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added state variables** to track approval processing stages across multiple transactions
 * 2. **Implemented multi-stage approval workflow** requiring 3 separate transactions to complete
 * 3. **Introduced external calls before state updates** at each stage, creating reentrancy opportunities
 * 4. **State persistence** allows manipulation of approval states between transactions
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker calls receiveApproval with stage 0, initializes pendingApprovals and sets approvalInProgress=true
 * 2. **Transaction 2**: Attacker calls receiveApproval with stage 1, triggers external call to malicious contract while approval is still in progress
 * 3. **Transaction 3**: During the external call in stage 2, attacker reenters receiveApproval, manipulating pendingApprovals before cleanup
 * 4. **Exploitation**: The attacker can drain funds by manipulating the pending approval amounts across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - Each stage must be completed in separate transactions due to the stage-based state machine
 * - The vulnerability exploits the persistent state between transactions where approvalInProgress remains true
 * - Single-transaction exploitation is impossible because the stages are designed to be processed sequentially
 * - The attacker needs to accumulate state changes across multiple calls to manipulate the approval amounts effectively
 * 
 * **Realistic Business Logic:**
 * This mimics real-world approval workflows where complex multi-step processes are required for security or compliance reasons, making the vulnerability realistic and subtle.
 */
pragma solidity ^0.4.16;

interface tokenRecipient {
    // Just the function signature as an interface should have
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external;
}

// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
contract ApprovalProcessor {
    // State variables to track approval processing stages
    mapping(address => mapping(address => uint256)) public pendingApprovals;
    mapping(address => mapping(address => bool)) public approvalInProgress;
    mapping(address => mapping(address => uint256)) public approvalStage;

    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external {
        // Multi-stage approval process to handle complex approval workflows
        uint256 currentStage = approvalStage[_from][_token];
        
        if (currentStage == 0) {
            // Stage 1: Initialize approval tracking
            pendingApprovals[_from][_token] = _value;
            approvalStage[_from][_token] = 1;
            approvalInProgress[_from][_token] = true;
            
            // External call to token contract for validation - VULNERABILITY: Before state update
            if (_token != address(0)) {
                // Removed 'try/catch', replaced with classic external call with low-level checks
                uint256 balance = TmrChainERC20(_token).balanceOf(_from);
                if (balance >= _value) {
                    // Process stage 1 validation
                    approvalStage[_from][_token] = 2;
                }
                // No catch, any failure will revert in this version of Solidity
            }
        } else if (currentStage == 1) {
            // Stage 2: Process pending approval
            if (pendingApprovals[_from][_token] > 0) {
                approvalStage[_from][_token] = 2;
                
                // External call to notify approval processor - VULNERABILITY: State still in progress
                if (_from != address(0)) {
                    // Classic external contract call
                    tokenRecipient(_from).receiveApproval(msg.sender, _value, _token, _extraData);
                    // No try/catch
                }
            }
        } else if (currentStage == 2) {
            // Stage 3: Finalize approval processing
            uint256 pendingValue = pendingApprovals[_from][_token];
            
            if (pendingValue > 0 && approvalInProgress[_from][_token]) {
                // External call to finalize with external service - VULNERABILITY: Before cleanup
                if (_token != address(0)) {
                    TmrChainERC20(_token).transfer(_from, pendingValue);
                }
                // VULNERABILITY: State cleanup happens after external calls
                // This allows reentrancy to manipulate state during external calls
                pendingApprovals[_from][_token] = 0;
                approvalInProgress[_from][_token] = false;
                approvalStage[_from][_token] = 0;
            }
        }
    }
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

contract TmrChainERC20 {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 6;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     */
    function  TmrChainERC20() public {
        totalSupply =1000000000000000;  // Update total supply with the decimal amount
        balanceOf[msg.sender] = 1000000000000000;        // Give the creator all initial tokens
        name = "TiMediaRun";                                   // Set the name for display purposes
        symbol = "TMR";                               // Set the symbol for display purposes
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
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
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
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
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
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
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
}
