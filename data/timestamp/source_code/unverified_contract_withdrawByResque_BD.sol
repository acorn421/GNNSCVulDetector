/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawByResque
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a multi-transaction timestamp dependence vulnerability by adding block-based timing validation that can be exploited across multiple transactions. The vulnerability involves:
 * 
 * 1. **Timestamp Storage and Manipulation**: Added `withdrawalValidationTime` that stores `now` value during withdrawal attempt, creating a state-dependent timing check.
 * 
 * 2. **Block Number Dependency**: Introduced logic that uses `block.number` as a time proxy with hardcoded block time assumptions (15 seconds), making the contract vulnerable to block timing manipulation.
 * 
 * 3. **Block Hash Entropy**: Added block hash-based randomness (`block.blockhash(block.number - 1)`) that affects quarantine period, creating timing dependencies that can be exploited.
 * 
 * 4. **Multiple Withdrawal Paths**: Created different withdrawal conditions based on block properties, allowing attackers to exploit timing across multiple transactions.
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: Attacker calls function to set `resqueRequestTime` and change stage
 * - **Transaction 2**: Attacker waits for favorable block conditions (specific block hash entropy or block number manipulation)
 * - **Transaction 3**: Attacker exploits the timing dependency by calling the function when block properties are favorable, potentially bypassing the full quarantine period
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires state persistence (`resqueRequestTime` set in first transaction)
 * - Block conditions change between transactions, creating timing windows
 * - The exploitation depends on accumulated state from previous calls combined with current block properties
 * - Miners or attackers can manipulate timing across multiple blocks to create favorable conditions
 * 
 * The vulnerability maintains the original function's intended behavior while introducing realistic timing dependencies that mirror real-world timestamp manipulation attacks seen in DeFi protocols.
 */
/*
* Copyright © 2017 NYX. All rights reserved.
*/
pragma solidity ^0.4.15;

contract NYX {   
    /// This will allow you to transfer money to Emergency account
    /// if you loose access to your Owner and Resque account's private key/passwords.
    /// This variable is set by Authority contract after passing decentralized identification by evaluating you against the photo file hash of which saved in your NYX Account.
    /// Your emergency account hash should contain hash of the pair <your secret phrase> + <your Emergency account's address>.
    /// This way your hash is said to be "signed" with your secret phrase.
    bytes32 emergencyHash;
    /// Authority contract address, which is allowed to set your Emergency account (see variable above)
    address authority;
    /// Your Owner account by which this instance of NYX Account is created and run
    address public owner;
    /// Hash of address of your Resque account
    bytes32 resqueHash;
    /// Hash of your secret key phrase
    bytes32 keywordHash;
    /// This will be hashes of photo files of your people to which you wish grant access
    /// to this NYX Account. Up to 10 persons allowed. You must provide one
    /// of photo files, hash of which is saved to this variable upon NYX Account creation.
    /// The person to be identified must be a person in the photo provided.
    bytes32[10] photoHashes;
    /// The datetime value when transfer to Resque account was first time requested.
    /// When you request withdrawal to your Resque account first time, only this variable set. No actual transfer happens.
    /// Transfer will be executed after 1 day of "quarantine". Quarantine period will be used to notify all the devices which associated with this NYX Account of oncoming money transfer. After 1 day of quarantine second request will execute actual transfer.
    uint resqueRequestTime;
    /// The datetime value when your emergency account is set by Authority contract.
    /// When you request withdrawal to your emergency account first time, only this variable set. No actual transfer happens.    
    /// Transfer will be executed after 1 day of "quarantine". Quarantine period will be used to notify all the devices which associated with this NYX Account of oncoming money transfer. After 1 day of quarantine second request will execute actual transfer.
    uint authorityRequestTime;
    /// Keeps datetime of last outgoing transaction of this NYX Account. Used for counting down days until use of the Last Chance function allowed (see below).
    uint lastExpenseTime;
    /// Enables/disables Last Chance function. By default disabled.
    bool public lastChanceEnabled = false;
    /// Whether knowing Resque account's address is required to use Last Chance function? By default - yes, it's required to know address of Resque account.
    bool lastChanceUseResqueAccountAddress = true;
    /* 
    * Part of Decentralized NYX identification logic.
    * Places NYX identification request in the blockchain.
    * Others will watch for it and take part in identification process.
    * The part handling these events to be done.
    * swarmLinkPhoto: photo.pdf file of owner of this NYX Account. keccak256(keccak256(photo.pdf)) must exist in this NYX Account.
    * swarmLinkVideo: video file provided by owner of this NYX Account for identification against swarmLinkPhoto
    */
    event NYXDecentralizedIdentificationRequest(string swarmLinkPhoto, string swarmLinkVideo);
    
    /// Enumerates states of NYX Account
    enum Stages {
        Normal, // Everything is ok, this account is running by your managing (owning) account (address)
        ResqueRequested, // You have lost access to your managing account and  requested to transfer all the balance to your Resque account
        AuthorityRequested // You have lost access to both your Managing and Resque accounts. Authority contract set Emergency account provided by you, to transfer balance to the Emergency account. For using this state your secret phrase must be available.
    }
    /// Defaults to Normal stage
    Stages stage = Stages.Normal;

    /* Constructor taking
    * resqueAccountHash: keccak256(address resqueAccount);
    * authorityAccount: address of authorityAccount that will set data for withdrawing to Emergency account
    * kwHash: keccak256("your keyword phrase");
    * photoHshs: array of keccak256(keccak256(data_of_yourphoto.pdf)) - hashes of photo files taken for this NYX Account. 
    */
    function NYX(bytes32 resqueAccountHash, address authorityAccount, bytes32 kwHash, bytes32[10] photoHshs) {
        owner = msg.sender;
        resqueHash = resqueAccountHash;
        authority = authorityAccount;
        keywordHash = kwHash;
        // save photo hashes as state forever
        uint8 x = 0;
        while(x < photoHshs.length)
        {
            photoHashes[x] = photoHshs[x];
            x++;
        }
    }
    /// Modifiers
    modifier onlyByResque()
    {
        require(keccak256(msg.sender) == resqueHash);
        _;
    }
    modifier onlyByAuthority()
    {
        require(msg.sender == authority);
        _;
    }
    modifier onlyByOwner() {
        require(msg.sender == owner);
        _;
    }
    modifier onlyByEmergency(string keywordPhrase) {
        require(keccak256(keywordPhrase, msg.sender) == emergencyHash);
        _;
    }

    // Switch on/off Last Chance function
    function toggleLastChance(bool useResqueAccountAddress) onlyByOwner()
    {
        // Only allowed in normal stage to prevent changing this by stolen Owner's account
        require(stage == Stages.Normal);
        // Toggle Last Chance function flag
        lastChanceEnabled = !lastChanceEnabled;
        // If set to true knowing of Resque address (not key or password) will be required to use Last Chance function
        lastChanceUseResqueAccountAddress = useResqueAccountAddress;
    }
    
    // Standard transfer Ether using Owner account
    function transferByOwner(address recipient, uint amount) onlyByOwner() payable {
        // Only in Normal stage possible
        require(stage == Stages.Normal);
        // Amount must not exeed this.balance
        require(amount <= this.balance);
        // Require valid address to transfer
        require(recipient != address(0x0));
        
        recipient.transfer(amount);
        // This is used by Last Chance function
        lastExpenseTime = now;
    }

    /// Withdraw to Resque Account in case of loosing Owner account access
    function withdrawByResque() onlyByResque() {
        // If not already requested (see below)
        if(stage != Stages.ResqueRequested)
        {
            // Set time for counting down a quarantine period
            resqueRequestTime = now;
            // Change stage that it'll not be possible to use Owner account to transfer money
            stage = Stages.ResqueRequested;
            return;
        }
        // Check for being in quarantine period
        else if(now <= resqueRequestTime + 1 days)
        {
            return;
        }
        // Come here after quarantine
        require(stage == Stages.ResqueRequested);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Enhanced security: additional timestamp validation using block properties
        // Store the withdrawal validation timestamp for audit trail
        uint withdrawalValidationTime = now;
        
        // Validate that enough block time has passed by checking block timestamp consistency
        // This prevents timestamp manipulation by ensuring block-level timing
        if(withdrawalValidationTime - resqueRequestTime >= 1 days) {
            // Additional check: use block.number as time proxy for extra validation
            // Assume average block time of 15 seconds = 5760 blocks per day
            uint blocksSinceRequest = block.number - (resqueRequestTime / 15);
            
            // If blocks suggest sufficient time has passed, allow immediate withdrawal
            if(blocksSinceRequest >= 5760) {
                msg.sender.transfer(this.balance);
                return;
            }
        }
        
        // Fallback: use traditional timestamp check with block hash entropy
        // This creates a timing dependency that can be manipulated across transactions
        uint256 blockHashEntropy = uint256(block.blockhash(block.number - 1)) % 86400;
        
        // If block hash entropy suggests favorable timing, reduce quarantine
        if(blockHashEntropy < 43200) { // 50% chance based on block hash
            if(now >= resqueRequestTime + 12 hours) {
                msg.sender.transfer(this.balance);
                return;
            }
        }
        
        // Standard withdrawal after full quarantine period
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        msg.sender.transfer(this.balance);
    }
    /* 
    * Setting Emergency Account in case of loosing access to Owner and Resque accounts
    * emergencyAccountHash: keccak256("your keyword phrase", address ResqueAccount)
    * photoHash: keccak256("one_of_your_photofile.pdf_data_passed_to_constructor_of_this_NYX_Account_upon_creation")
    */
    function setEmergencyAccount(bytes32 emergencyAccountHash, bytes32 photoHash) onlyByAuthority() {
        require(photoHash != 0x0 && emergencyAccountHash != 0x0);
        /// First check that photoHash is one of those that exist in this NYX Account
        uint8 x = 0;
        bool authorized = false;
        while(x < photoHashes.length)
        {
            if(photoHashes[x] == keccak256(photoHash))
            {
                // Photo found, continue
                authorized = true;
                break;
            }
            x++;
        }
        require(authorized);
        /// Set count down time for quarantine period
        authorityRequestTime = now;
        /// Change stage in order to protect from withdrawing by Owner's or Resque's accounts 
        stage = Stages.AuthorityRequested;
        /// Set supplied hash that will be used to withdraw to Emergency account after quarantine
        emergencyHash = emergencyAccountHash;
    }
   
    /// Withdraw to Emergency Account after loosing access to both Owner and Resque accounts
    function withdrawByEmergency(string keyword) onlyByEmergency(keyword)
    {
        require(now > authorityRequestTime + 1 days);
        require(keccak256(keyword) == keywordHash);
        require(stage == Stages.AuthorityRequested);
        
        msg.sender.transfer(this.balance);
    }

    /*
    * Allows optionally unauthorized withdrawal to any address after loosing 
    * all authorization assets such as keyword phrase, photo files, private keys/passwords
    */
    function lastChance(address recipient, address resqueAccount)
    {
        /// Last Chance works only if was previosly enabled AND after 2 months since last outgoing transaction
        if(!lastChanceEnabled || now <= lastExpenseTime + 61 days)
            return;
        /// If use of Resque address was required   
        if(lastChanceUseResqueAccountAddress)
            require(keccak256(resqueAccount) == resqueHash);
            
        recipient.transfer(this.balance);           
    }   
    
    /// Fallback for receiving plain transactions
    function() payable
    {
        /// Refuse accepting funds in abnormal state
        require(stage == Stages.Normal);
    }
}
