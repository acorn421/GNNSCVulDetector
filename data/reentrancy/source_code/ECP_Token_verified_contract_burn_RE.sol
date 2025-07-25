/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burning registry contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Setup Transaction**: Attacker deploys a malicious burning registry contract that implements IBurningRegistry interface
 * 2. **State Accumulation**: Attacker needs to accumulate tokens over multiple transactions to maximize exploit potential
 * 3. **Exploitation Transaction**: When burn() is called, the external call to burningRegistry.notifyBurn() allows reentrancy back into burn() or other functions before state updates complete
 * 
 * The vulnerability is stateful because:
 * - The burningRegistry address is persistent contract state
 * - Token balances and totalSupply are persistent state that can be manipulated
 * - The exploit effectiveness depends on accumulated token holdings across multiple transactions
 * 
 * Multi-transaction exploitation pattern:
 * - Transaction 1: Deploy malicious registry and register it (if registry is settable)
 * - Transaction 2-N: Accumulate tokens through normal operations
 * - Transaction N+1: Call burn() which triggers reentrancy, allowing double-spending or state manipulation before balances are updated
 * 
 * The external call placement before state updates violates the Checks-Effects-Interactions pattern, creating a window where the contract state is inconsistent and vulnerable to reentrancy attacks.
 */
pragma solidity ^0.4.20;

contract tokenRecipient {
    function receiveApproval(address from, uint256 value, address token, bytes extraData) public;
}

// Interface for the burning registry (to preserve vulnerability as intended)
interface IBurningRegistry {
    function notifyBurn(address from, uint256 value) external;
}

contract ECP_Token {
    /* Variables For Contract */
    string  public name;                                                        // Variable To Store Name
    string  public symbol;                                                      // Variable To Store Symbol
    uint8   public decimals;                                                    // Variable To Store Decimals
    uint256 public totalSupply;                                                 // Variable To Store Total Supply Of Tokens
    uint256 public remaining;                                                   // Variable To Store Smart Remaining Tokens
    address public owner;                                                       // Variable To Store Smart Contract Owner
    uint    public icoStatus;                                                   // Variable To Store Smart Contract Status ( Enable / Disabled )
    address public benAddress;                                                  // Variable To Store Ben Address
    address public bkaddress;                                                   // Variable To Store Backup Ben Address
    uint    public allowTransferToken;                                          // Variable To Store If Transfer Is Enable Or Disabled

    address public burningRegistry;                                             // Added missing burningRegistry variable

    /* Array For Contract*/
    mapping (address => uint256) public balanceOf;                              // Arrary To Store Ether Addresses
    mapping (address => mapping (address => uint256)) public allowance;         // Arrary To Store Ether Addresses For Allowance
    mapping (address => bool) public frozenAccount;                             // Arrary To Store Ether Addresses For Frozen Account

    /* Events For Contract  */
    event FrozenFunds(address target, bool frozen);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event TokenTransferEvent(address indexed from, address indexed to, uint256 value, string typex);

    /* Initialize Smart Contract */
    constructor() public {
        totalSupply = 15000000000000000000000000000;                              // Total Supply 15 Billion Tokens
        owner =  msg.sender;                                                      // Smart Contract Owner
        balanceOf[owner] = totalSupply;                                           // Credit Tokens To Owner
        name = "ECP Token";                                                       // Set Name Of Token
        symbol = "ECP";                                                           // Set Symbol Of Token
        decimals = 18;                                                            // Set Decimals
        remaining = totalSupply;                                                  // Set How Many Tokens Left
        icoStatus = 1;                                                            // Set ICO Status As Active At Beginning
        benAddress = 0xe4a7a715bE044186a3ac5C60c7Df7dD1215f7419;
        bkaddress  = 0x44e00602e4B8F546f76983de2489d636CB443722;
        allowTransferToken = 1;                                                   // Default Set Allow Transfer To Active
        burningRegistry = address(0);                                             // Initialize burningRegistry
    }

    modifier onlyOwner() {
        require((msg.sender == owner) || (msg.sender ==  bkaddress));
        _;
    }

    function () public payable {
    }

    function sendToMultipleAccount(address[] dests, uint256[] values) public onlyOwner returns (uint256) {
        uint256 i = 0;
        while (i < dests.length) {
            if(remaining > 0) {
                _transfer(owner, dests[i], values[i]);  // Transfer Token Via Internal Transfer Function
                TokenTransferEvent(owner, dests[i], values[i],'MultipleAccount'); // Raise Event After Transfer
            } else {
                revert();
            }
            i += 1;
        }
        return(i);
    }

    function sendTokenToSingleAccount(address receiversAddress, uint256 amountToTransfer) public onlyOwner {
        if (remaining > 0) {
            _transfer(owner, receiversAddress, amountToTransfer);  // Transfer Token Via Internal Transfer Function
            TokenTransferEvent(owner, receiversAddress, amountToTransfer,'SingleAccount'); // Raise Event After Transfer
        } else {
            revert();
        }
    }

    function setTransferStatus (uint st) public onlyOwner {
        allowTransferToken = st;
    }

    function changeIcoStatus (uint8 st) public onlyOwner {
        icoStatus = st;
    }

    function withdraw(uint amountWith) public onlyOwner {
        if((msg.sender == owner) || (msg.sender ==  bkaddress)) {
            benAddress.transfer(amountWith);
        } else {
            revert();
        }
    }

    function withdraw_all() public onlyOwner {
        if((msg.sender == owner) || (msg.sender ==  bkaddress) ) {
            uint256 amountWith = this.balance - 10000000000000000;
            benAddress.transfer(amountWith);
        } else {
            revert();
        }
    }

    function mintToken(uint256 tokensToMint) public onlyOwner {
        if(tokensToMint > 0) {
            uint256 totalTokenToMint = tokensToMint * (10 ** 18);               // Calculate Tokens To Mint
            balanceOf[owner] += totalTokenToMint;                               // Credit To Owners Account
            totalSupply += totalTokenToMint;                                    // Update Total Supply
            remaining += totalTokenToMint;                                      // Update Remaining
            Transfer(0, owner, totalTokenToMint);                               // Raise The Event
        }
    }

    function adm_trasfer(address _from,address _to, uint256 _value) public onlyOwner {
        _transfer(_from, _to, _value);
    }

    function freezeAccount(address target, bool freeze) public onlyOwner {
        frozenAccount[target] = freeze;
        FrozenFunds(target, freeze);
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balanceOf[_owner];
    }

    function totalSupply_() private constant returns (uint256 tsupply) { // Renamed to avoid clash with variable
        tsupply = totalSupply;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        balanceOf[owner] = 0;
        balanceOf[newOwner] = remaining;
        owner = newOwner;
    }

    function _transfer(address _from, address _to, uint _value) internal {
        if(allowTransferToken == 1 || _from == owner ) {
            require(!frozenAccount[_from]);                                   // Prevent Transfer From Frozenfunds
            require (_to != 0x0);                                             // Prevent Transfer To 0x0 Address.
            require (balanceOf[_from] > _value);                              // Check If The Sender Has Enough Tokens To Transfer
            require (balanceOf[_to] + _value > balanceOf[_to]);               // Check For Overflows
            balanceOf[_from] -= _value;                                       // Subtract From The Sender
            balanceOf[_to] += _value;                                         // Add To The Recipient
            Transfer(_from, _to, _value);                                     // Raise Event After Transfer
        } else {
            revert();
        }
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require (_value < allowance[_from][msg.sender]);                      // Check Has Permission To Transfer
        allowance[_from][msg.sender] -= _value;                               // Minus From Available
        _transfer(_from, _to, _value);                                        // Credit To Receiver
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require (balanceOf[msg.sender] > _value);                             // Check If The Sender Has Enough Balance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify burning registry contract before updating state
        if (burningRegistry != address(0)) {
            IBurningRegistry(burningRegistry).notifyBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                                      // Subtract From The Sender
        totalSupply -= _value;                                                // Updates TotalSupply
        remaining -= _value;                                                  // Update Remaining Tokens
        Burn(msg.sender, _value);                                             // Raise Event
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                                  // Check If The Target Has Enough Balance
        require(_value <= allowance[_from][msg.sender]);                      // Check Allowance
        balanceOf[_from] -= _value;                                           // Subtract From The Targeted Balance
        allowance[_from][msg.sender] -= _value;                               // Subtract From The Sender's Allowance
        totalSupply -= _value;                                                // Update TotalSupply
        remaining -= _value;                                                  // Update Remaining
        Burn(_from, _value);
        return true;
    }
} //  ECP Smart Contract End
