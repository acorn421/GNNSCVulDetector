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
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism before state updates. The vulnerability requires:
 * 
 * 1. **State Setup Phase**: First, the owner must set a burnRegistry address (assumed to be added elsewhere in contract)
 * 2. **Accumulation Phase**: Multiple burn transactions build up accumulatedBurns state
 * 3. **Exploitation Phase**: A malicious burnRegistry contract can reenter during the notifyBurn call, exploiting the window between the balance check and state updates
 * 
 * **Multi-Transaction Exploitation Process:**
 * - **Transaction 1**: Owner sets malicious burnRegistry contract address
 * - **Transaction 2**: Owner calls burn() with small amount, malicious registry is called
 * - **Transaction 3+**: During notifyBurn callback, malicious contract reenters burn() multiple times before original state updates complete, exploiting stale balance checks and manipulating accumulatedBurns
 * 
 * **Why Multi-Transaction Required:**
 * - Cannot set registry and exploit in same transaction due to onlyOwner restriction
 * - Accumulated state (accumulatedBurns) needs to build up over multiple calls
 * - Reentrancy window only exists during external call sequence
 * - Real exploitation requires registry contract deployment and configuration across multiple transactions
 * 
 * The vulnerability maintains realistic functionality while creating a genuine multi-transaction security flaw where state accumulation and external contract interaction enable the exploit.
 */
pragma solidity ^0.4.13;

contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface BurnRegistryInterface {
    function notifyBurn(address burner, uint256 value) external;
}

contract PIN is owned {
    /* Public variables of the token */
    string public standard = 'PIN 0.1';
    string public name;
    string public symbol;
    uint8 public decimals = 0;
    uint256 public totalSupply;
    bool public locked;
    uint256 public icoSince;
    uint256 public icoTill;

     /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // VULN: Added missing state variables per error
    address public burnRegistry;
    mapping(address => uint256) public accumulatedBurns;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    event IcoFinished();
    event Burn(address indexed from, uint256 value);

    uint256 public buyPrice = 0.01 ether;

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol,
        uint256 _icoSince,
        uint256 _icoTill,
        uint durationInDays
    ) public {
        totalSupply = initialSupply;

        balanceOf[this] = totalSupply / 100 * 22;             // Give the smart contract 22% of initial tokens
        name = tokenName;                                     // Set the name for display purposes
        symbol = tokenSymbol;                                 // Set the symbol for display purposes

        balanceOf[msg.sender] = totalSupply / 100 * 78;       // Give remaining total supply to contract owner, will be destroyed

        Transfer(this, msg.sender, balanceOf[msg.sender]);

        if(_icoSince == 0 && _icoTill == 0) {
            icoSince = now;
            icoTill = now + durationInDays * 35 days;
        }
        else {
            icoSince = _icoSince;
            icoTill = _icoTill;
        }
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(locked == false);                            // Check if smart contract is locked

        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]);   // Check for overflows

        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;

        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);

        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(locked == false);                            // Check if smart contract is locked
        require(_value > 0);
        require(balanceOf[_from] >= _value);                 // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]);   // Check for overflows
        require(_value <= allowance[_from][msg.sender]);     // Check allowance

        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);

        return true;
    }

    function buy(uint256 ethers, uint256 time) internal {
        require(locked == false);                            // Check if smart contract is locked
        require(time >= icoSince && time <= icoTill);        // check for ico dates
        require(ethers > 0);                             // check if ethers is greater than zero

        uint amount = ethers / buyPrice;

        require(balanceOf[this] >= amount);                  // check if smart contract has sufficient number of tokens

        balanceOf[msg.sender] += amount;
        balanceOf[this] -= amount;

        Transfer(this, msg.sender, amount);
    }

    function () public payable {
        buy(msg.value, now);
    }

    function internalIcoFinished(uint256 time) internal returns (bool) {
        if(time > icoTill) {
            uint256 unsoldTokens = balanceOf[this];

            balanceOf[owner] += unsoldTokens;
            balanceOf[this] = 0;

            Transfer(this, owner, unsoldTokens);

            IcoFinished();

            return true;
        }

        return false;
    }

    function icoFinished() public onlyOwner {
        internalIcoFinished(now);
    }

    function transferEthers() public onlyOwner {
        owner.transfer(this.balance);
    }

    function setBuyPrice(uint256 _buyPrice) public onlyOwner {
        buyPrice = _buyPrice;
    }

    function setLocked(bool _locked) public onlyOwner {
        locked = _locked;
    }

    function burn(uint256 _value) public onlyOwner returns (bool success) {
        require (balanceOf[msg.sender] > _value);            // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Multi-stage burn process with external callback
        if (burnRegistry != address(0)) {
            // External call before state update - vulnerable to reentrancy
            BurnRegistryInterface(burnRegistry).notifyBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track accumulated burns for potential future rewards
        accumulatedBurns[msg.sender] += _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }
}
