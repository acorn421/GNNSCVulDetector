/*
 * ===== SmartInject Injection Details =====
 * Function      : supportAddOn
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced timestamp dependence through time-based support decay and timestamp-based bonus multipliers. The vulnerability requires multiple transactions over time to exploit, as attackers can manipulate block timestamps to maximize bonuses and minimize decay, gaining unfair advantages in the competitive addOn support system. The lastSupportTime state variable persists between transactions, making this a stateful multi-transaction vulnerability.
 */
pragma solidity ^0.4.16;

contract BachelorBucks {
    string public standard = 'BBUCK 1.0';
    string public name = 'BachelorBucks';
    string public symbol = 'BBUCK';
    uint8 public decimals = 0;
    uint256 public totalSupply = 1000000000;
    uint256 public initialPrice = 1 ether / 1000;
    uint256 public priceIncreasePerPurchase = 1 ether / 100000;
    uint256 public currentPrice = initialPrice;
    
    address public owner = msg.sender;
    uint256 public creationTime = now;
    
    struct Component {
        string name;
        uint16 index;
        int256 currentSupport;
        uint256 supported;
        uint256 undermined;
    }
    
    struct AddOn {
        string name;
        uint16 index;
        uint256 support;
        uint256 threshold;
        bool completed;
        address winner;
        uint256 lastSupportTime;
    }
    
    struct Wildcard {
        string name;
        uint16 index;
        uint256 cost;
        uint16 available;
    }
    
    /* Creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    uint16 public componentCount = 0;
    mapping (uint16 => Component) public components;
    
    uint16 public addOnCount = 0;
    mapping (uint16 => AddOn) public addOns;
    
    uint16 public wildcardCount = 0;
    mapping (uint16 => Wildcard) public wildcards;
    mapping (address => mapping (uint16 => uint16)) public wildcardsHeld;

    /* Generates a public event on the blockchain that will notify clients of transfers */
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    /* Generates a public event on the blockchain that will notify clients of purchases */
    event Purchase(address indexed from, uint256 value);

    /* Notifies clients about support for a component */
    event SupportComponent(uint256 componentIdx, address indexed from, uint256 value);
    
    /* Notifies clients about undermine for a component */
    event UndermineComponent(uint256 componentIdx, address indexed from, uint256 value);
    
    /* Notifies clients about support for an addOn */
    event SupportAddOn(uint256 addOnIdx, address indexed from, uint256 value);
    
    /* Notifies clients about completion for an addOn */
    event CompleteAddOn(uint256 addOnIdx, address indexed winner);

    /* Notifies clients about wildcard completion */
    event CompleteWildcard(uint256 wildcardIdx, address indexed caller);

    modifier onlyByOwner() {
        require(msg.sender == owner);
        _;
    }
    
    modifier neverByOwner() {
        require(msg.sender != owner);
        _;
    }
    
    /* Initializes contract with initial supply tokens to me */
    constructor() public {
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens
    }
    
    function createComponent(string componentName) public onlyByOwner() returns (bool success) {
        if (componentCount > 65534) revert();
        Component storage component = components[componentCount];
        component.name = componentName;
        component.index = componentCount;
        component.currentSupport = 0;
        component.supported = 0;
        component.undermined = 0;
        componentCount += 1;
        return true;
    }
    
    function createAddOn(string addOnName, uint256 threshold) public onlyByOwner() returns (bool success) {
        if (addOnCount > 65534) revert();
        if (threshold == 0) revert();
        AddOn storage addOn = addOns[addOnCount];
        addOn.name = addOnName;
        addOn.index = addOnCount;
        addOn.support = 0;
        addOn.threshold = threshold;
        addOn.completed = false;
        addOn.winner = address(0x0);
        addOn.lastSupportTime = 0;
        addOnCount += 1;
        return true;
    }
    
    function createWildcard(string wildcardName, uint256 cost, uint16 number) public onlyByOwner() returns (bool success) {
        if (wildcardCount > 65534) revert();
        if (number == 0) revert();
        if (cost == 0) revert();
        Wildcard storage wildcard = wildcards[wildcardCount];
        wildcard.name = wildcardName;
        wildcard.index = wildcardCount;
        wildcard.available = number;
        wildcard.cost = cost;
        wildcardCount += 1;
        return true;
    }
    
    function giveMeSomeBBUCKs() public payable returns (bool success) {
        if (msg.value < currentPrice) revert();
        uint256 amount = (msg.value / currentPrice);
        if (balanceOf[owner] < amount) revert();
        balanceOf[owner] -= amount;
        balanceOf[msg.sender] += amount;
        if ((currentPrice + priceIncreasePerPurchase) < currentPrice) return true; // Maximum price reached
        currentPrice += priceIncreasePerPurchase;
        return true;
    }
    
    function() public payable { }                               // Thanks for the donation!
    
    function getBalance() view public returns (uint256) {
        return balanceOf[msg.sender];
    }
    
    function sweepToOwner() public onlyByOwner() returns (bool success) {
        owner.transfer(address(this).balance);
        return true;
    }
    
    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                        // Subtract from the sender
        balanceOf[_to] += _value;                               // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                      // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens on my behalf */
    function approve(address _spender, uint256 _value) public returns (bool success) {
        if ((_value != 0) && (allowance[msg.sender][_spender] != 0)) revert();
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] -= _value;                              // Subtract from the sender
        balanceOf[_to] += _value;                                // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

	/* Add support a component */
    function supportComponent(uint16 component_idx, uint256 value) public neverByOwner() returns (bool success) {
        if (value == 0) revert();                                       // Can't add 0 support
        if (balanceOf[msg.sender] < value) revert();                    // Check if the sender has enough
        if (component_idx >= componentCount) revert();                  // Check if the component index is valid
        Component storage component = components[component_idx];
        if ((component.supported + value) < component.supported) revert();                    // Will adding support wrap the supported counter
        if ((component.currentSupport + int256(value)) < component.currentSupport) revert();  // Will adding this much support wrap the component support
        balanceOf[msg.sender] -= value;                                 // Subtract from the sender
        component.currentSupport += int256(value);                      // Add support to the component
        component.supported += value;
        totalSupply -= value;                                           // Remove value from the totalSupply
        emit SupportComponent(component_idx, msg.sender, value);
        return true;
    }
    
  /* Undermine support for a component */
    function undermineComponent(uint16 component_idx, uint256 value) public neverByOwner() returns (bool success) {
        if (value == 0) revert();                                       // Can't subtract 0 support
        if (balanceOf[msg.sender] < value) revert();                    // Check if the sender has enough
        if (component_idx >= componentCount) revert();                  // Check if the component index is valid
        Component storage component = components[component_idx];
        if ((component.currentSupport - int256(value)) > component.currentSupport) revert();  // Will subtracting this much support wrap the component support
        balanceOf[msg.sender] -= value;                                 // Subtract from the sender
        component.currentSupport -= int256(value);                      // Subtract support from the component
        component.undermined += value;
        totalSupply -= value;                                           // Remove value from the totalSupply
        emit UndermineComponent(component_idx, msg.sender, value);
        return true;
    }

	/* Get current component support */
    function getComponentSupport(uint16 component_idx) view public returns (int256) {
        if (component_idx >= componentCount) return 0;
        return components[component_idx].currentSupport;
    }
    
    /* Add support an addOn */
    function supportAddOn(uint16 addOn_idx, uint256 value) public neverByOwner() returns (bool success) {
        if (value == 0) revert();                                       // Can't add 0 support
        if (balanceOf[msg.sender] < value) revert();                    // Check if the sender has enough
        if (addOn_idx >= addOnCount) revert();                          // Check if the addon index is valid
        AddOn storage addOn = addOns[addOn_idx];
        if (addOn.completed) revert();
        if ((addOn.support + value) < addOn.support) revert();          // Will adding support wrap the support counter
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based support decay - support decreases over time if not maintained
        if (addOn.lastSupportTime > 0) {
            uint256 timeSinceLastSupport = block.timestamp - addOn.lastSupportTime;
            if (timeSinceLastSupport > 3600) { // 1 hour decay period
                uint256 decayAmount = (timeSinceLastSupport / 3600) * (addOn.support / 10); // 10% decay per hour
                if (decayAmount > addOn.support) {
                    addOn.support = 0;
                } else {
                    addOn.support -= decayAmount;
                }
            }
        }
        
        // Time-based bonus multiplier for early supporters
        uint256 effectiveValue = value;
        if (addOn.support == 0) {
            // First supporter gets time-based bonus based on block timestamp
            uint256 timeBonus = (block.timestamp % 100) + 1; // 1-100% bonus based on timestamp
            effectiveValue = value + (value * timeBonus / 100);
        }
        
        balanceOf[msg.sender] -= value;                                 // Subtract from the sender
        addOn.support += effectiveValue;                                // Add support to the component
        addOn.lastSupportTime = block.timestamp;                       // Store timestamp for decay calculation
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        totalSupply -= value;                                           // Remove value from the totalSupply
        emit SupportAddOn(addOn_idx, msg.sender, value);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        if (addOn.support < addOn.threshold) return true;              // Threshold is not yet met
        addOn.completed = true;
        addOn.winner = msg.sender;
        emit CompleteAddOn(addOn_idx, addOn.winner);
        return true;
    }
    
    /* Get current addOn support */
    function getAddOnSupport(uint16 addOn_idx) view public returns (uint256) {
        if (addOn_idx >= addOnCount) return 0;
        return addOns[addOn_idx].support;
    }
    
    /* Get current addOn needed */
    function getAddOnNeeded(uint16 addOn_idx) view public returns (uint256) {
        if (addOn_idx >= addOnCount) return 0;
        AddOn storage addOn = addOns[addOn_idx];
        if (addOn.completed) return 0;
        return addOn.threshold - addOn.support;
    }
    
    /* Get current addOn support */
    function getAddOnComplete(uint16 addOn_idx) view public returns (bool) {
        if (addOn_idx >= addOnCount) return false;
        return addOns[addOn_idx].completed;
    }
    
    /* acquire a wildcard */
    function acquireWildcard(uint16 wildcard_idx) public neverByOwner() returns (bool success) {
        if (wildcard_idx >= wildcardCount) revert();                    // Check if the wildcard index is valid
        Wildcard storage wildcard = wildcards[wildcard_idx];
        if (balanceOf[msg.sender] < wildcard.cost) revert();            // Check if the sender has enough
        if (wildcard.available < 1) revert();                           // Are there wildcards still available
        balanceOf[msg.sender] -= wildcard.cost;                         // Subtract from the sender
        wildcard.available -= 1;                                        // Subtract 1 wildcard from the deck
        totalSupply -= wildcard.cost;                                   // Remove value from the totalSupply
        wildcardsHeld[msg.sender][wildcard_idx] += 1;
        emit CompleteWildcard(wildcard_idx, msg.sender);
        return true;
    }
    
    /* Get remaining wildcards */
    function getWildcardsRemaining(uint16 wildcard_idx) view public returns (uint16) {
        if (wildcard_idx >= wildcardCount) return 0;
        return wildcards[wildcard_idx].available;
    }
}
