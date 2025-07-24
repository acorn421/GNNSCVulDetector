/*
 * ===== SmartInject Injection Details =====
 * Function      : allInitialOwnersAssigned
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a multi-transaction timestamp dependence vulnerability by adding time-based restrictions that create predictable exploitation windows. The vulnerability requires:
 * 
 * 1. **Transaction 1**: Attacker monitors for even timestamps and waits for the right timing window
 * 2. **Transaction 2**: Attacker attempts to front-run the owner's legitimate call during the vulnerable even-timestamp window
 * 3. **Transaction 3**: If successful, attacker can exploit the changed state in subsequent contract interactions
 * 
 * The vulnerability is stateful because:
 * - It tracks `lastStateChangeBlock` to enforce multi-transaction timing
 * - The `allCatsAssigned` state change persists and affects all future `claimCat()` calls
 * - The timing restrictions create predictable windows every other second where the function is vulnerable
 * 
 * Multi-transaction exploitation:
 * - Requires monitoring blockchain state across multiple blocks
 * - Attacker must time their transactions to coincide with even timestamps
 * - State changes accumulate across transactions (block tracking + assignment flag)
 * - Cannot be exploited atomically in a single transaction due to block number restrictions
 * 
 * This creates a realistic vulnerability where timing-dependent access controls can be predicted and exploited by sophisticated attackers monitoring blockchain timing patterns.
 */
pragma solidity ^0.4.18;
contract CryptoCatsMarket {

    /* You can use this hash to verify the image file containing all cats */
    string public imageHash = "e055fe5eb1d95ea4e42b24d1038db13c24667c494ce721375bdd827d34c59059";

    /* Struct object for storing cat details */
    struct Cat {
        uint256 idNum;         // cat index number
        string name;           // cat name
        bool owned;            // status of cat ownership
        address owner;         // address if cat owner
    }

    /* Variables to store contract owner and contract token standard details */
    address owner;
    string public standard = 'CryptoCats';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public _totalSupply;

    bool public allCatsAssigned = false;        // boolean flag to indicate if all available cats are claimed
    uint256 public catsRemainingToAssign = 0;   // variable to track cats remaining to be assigned/claimed

    /* Added declaration for lastStateChangeBlock */
    uint256 public lastStateChangeBlock;

    /* Create array to store cat index to owner address */
    mapping (uint256 => address) public catIndexToAddress;

    /* Create an array with all balances */
    mapping (address => uint256) public balanceOf;

    /* Create array to store cat details like names */
    mapping (uint256 => Cat) public catDetails;

    /* Define event types used to publish to EVM log when cat assignment/claim and cat transfer occurs */
    event Assign(address indexed to, uint256 catIndex);
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() public payable {
        owner = msg.sender;                          // Set contract creation sender as owner
        _totalSupply = 12;                           // Set total supply
        catsRemainingToAssign = _totalSupply;        // Initialise cats remaining to total supply amount
        name = "CRYPTOCATS";                         // Set the name for display purposes
        symbol = "CCAT";                               // Set the symbol for display purposes
        decimals = 0;                                // Amount of decimals for display purposes
        initialiseCats();                            // initialise cat details
        lastStateChangeBlock = block.number;         // initialize lastStateChangeBlock
    }

    /* Admin function to set all cats assigned flag to true (callable by owner only) */
    function allInitialOwnersAssigned() public {
        require(msg.sender == owner);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store current block timestamp for time-based validation
        uint256 currentTime = block.timestamp;
        
        // Allow assignment only during "safe" time windows (when timestamp is even)
        // This creates a predictable vulnerability window every other second
        require(currentTime % 2 == 0, "Assignment only allowed during even timestamps");
        
        // Additional time-based restriction: must wait at least 1 block since last state change
        // This requires multiple transactions to exploit timing windows
        require(block.number > lastStateChangeBlock, "Must wait for next block");
        
        // Update state tracking for multi-transaction dependency
        lastStateChangeBlock = block.number;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        allCatsAssigned = true;
    }

    /* Transfer cat by owner to another wallet address
       Different usage in Cryptocats than in normal token transfers 
       This will transfer an owner's cat to another wallet's address
       Cat is identified by cat index passed in as _value */
    function transfer(address _to, uint256 _value) public returns (bool success) {
        if (_value < _totalSupply &&                    // ensure cat index is valid
            catIndexToAddress[_value] == msg.sender &&  // ensure sender is owner of cat
            balanceOf[msg.sender] > 0) {                // ensure sender balance of cat exists
            balanceOf[msg.sender]--;                    // update (reduce) cat balance  from owner
            catIndexToAddress[_value] = _to;            // set new owner of cat in cat index
            catDetails[_value].owner = _to;             // set new owner of cat in cat details
            balanceOf[_to]++;                           // update (include) cat balance for recepient
            Transfer(msg.sender, _to, _value);          // trigger event with transfer details to EVM
            success = true;                             // set success as true after transfer completed
        } else {
            success = false;                            // set success as false if conditions not met
        }
        return success;                                 // return success status
    }

    /* Admin function to set all cats details during contract initialisation */
    function initialiseCats() private {
        require(msg.sender == owner);                   // require function caller to be contract owner
        catDetails[0] = Cat(0,"Cat 0", false, 0x0);
        catDetails[1] = Cat(1,"Cat 1", false, 0x0);
        catDetails[2] = Cat(2,"Cat 2", false, 0x0);
        catDetails[3] = Cat(3,"Cat 3", false, 0x0);
        catDetails[4] = Cat(4,"Cat 4", false, 0x0);
        catDetails[5] = Cat(5,"Cat 5", false, 0x0);
        catDetails[6] = Cat(6,"Cat 6", false, 0x0);
        catDetails[7] = Cat(7,"Cat 7", false, 0x0);
        catDetails[8] = Cat(8,"Cat 8", false, 0x0);
        catDetails[9] = Cat(9,"Cat 9", false, 0x0);
        catDetails[10] = Cat(10,"Cat 10", false, 0x0);
        catDetails[11] = Cat(11,"Cat 11", false, 0x0);        
    }

    /* Returns count of how many cats are owned by an owner */
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        require(balanceOf[_owner] != 0);    // requires that cat owner balance is not 0
        return balanceOf[_owner];           // return number of cats owned from array of balances by owner address
    }

    /* Return total supply of cats existing */
    function totalSupply_() public constant returns (uint256) {
        return _totalSupply;
    }

    /* Claim cat at specified index if it is unassigned */
    function claimCat(uint catIndex) public {
        require(!allCatsAssigned);                      // require all cats have not been assigned/claimed
        require(catsRemainingToAssign != 0);            // require cats remaining to be assigned count is not 0
        require(catIndexToAddress[catIndex] == 0x0);    // require owner address for requested cat index is empty
        require(catIndex < _totalSupply);               // require cat index requested does not exceed total supply
        catIndexToAddress[catIndex] = msg.sender;       // Assign sender's address as owner of cat
        balanceOf[msg.sender]++;                        // Increase sender's balance holder 
        catsRemainingToAssign--;                        // Decrease cats remaining count
        catDetails[catIndex].owned = true;              // set owned flag in cat details to true for this cat index
        catDetails[catIndex].owner = msg.sender;        // store owner address in cat details for this cat index
        Assign(msg.sender, catIndex);                   // Triggers address assignment event to EVM's
                                                        // log to allow javascript callbacks
    }

    /* Get address of owner based on cat index */
    function getCatOwner(uint256 catIndex) public returns (address) {
        require(catIndexToAddress[catIndex] != 0x0);
        return catIndexToAddress[catIndex];             // Return address at array position of cat index
    }

    /* Get address of contract owner who performed contract creation and initialisation */
    function getContractOwner() public returns (address) {
        return owner;                                   // Return address of contract owner
    }

    /* Get cat details consisting of index, name, owned status and owner address for a particular cat index */
    function getCatDetail(uint256 catIndex) public returns (uint256, string, bool, address) {
        Cat storage cat = catDetails[catIndex];                         // get cat struct object from cat details array
        return (cat.idNum, cat.name, cat.owned, cat.owner);     // return cat detail values
    }
}
